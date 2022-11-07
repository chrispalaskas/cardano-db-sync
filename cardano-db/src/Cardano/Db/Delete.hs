{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Cardano.Db.Delete
  ( deleteBlocksSlotNo
  , deleteBlocksSlotNoNoTrace
  , deleteDelistedPool
  , deleteBlocksBlockId
  , deleteBlock
  ) where

import           Cardano.Slotting.Slot (SlotNo (..))

import           Control.Monad.Extra (whenJust)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Trans.Reader (ReaderT)

import           Cardano.BM.Trace (Trace, logWarning, nullTracer)

import           Database.Esqueleto.Experimental (PersistEntity, PersistField, persistIdField)
import           Database.Persist.Sql (PersistEntityBackend, SqlBackend, delete, selectKeysList, (==.), (>=.))
import           Database.Persist.Class.PersistQuery (deleteWhere)
import           Data.ByteString (ByteString)
import           Data.Maybe (isJust)
import           Data.Text (Text)

import           Cardano.Db.MinId
import           Cardano.Db.Query hiding (isJust)
import           Cardano.Db.Schema
import           Cardano.Db.Text

deleteBlocksSlotNoNoTrace :: MonadIO m => SlotNo -> ReaderT SqlBackend m Bool
deleteBlocksSlotNoNoTrace = deleteBlocksSlotNo nullTracer

-- | Delete a block if it exists. Returns 'True' if it did exist and has been
-- deleted and 'False' if it did not exist.
deleteBlocksSlotNo :: MonadIO m => Trace IO Text -> SlotNo -> ReaderT SqlBackend m Bool
deleteBlocksSlotNo trce (SlotNo slotNo) = do
  mBlockId <- queryBlockSlotNo slotNo
  case mBlockId of
    Nothing -> pure False
    Just blockId -> do
      deleteBlocksBlockId trce blockId
      pure True

-- | Delete starting from a 'BlockId'.
deleteBlocksBlockId :: MonadIO m => Trace IO Text -> BlockId -> ReaderT SqlBackend m ()
deleteBlocksBlockId trce blockId = do
    blockIds <- undefined blockId -- TODO
    (cminIds, completed) <- findMinIdsRec blockIds mempty
    minIds <- if completed then pure cminIds else completeMinId blockId cminIds
    deleteTablesAfterBlockId blockId (minTxId minIds) (minTxInId minIds) (minTxOutId minIds) (minMaTxOutId minIds)

  where
    findMinIdsRec :: MonadIO m => [BlockId] -> MinIds -> ReaderT SqlBackend m (MinIds, Bool)
    findMinIdsRec [] minIds = pure (minIds, True)
    findMinIdsRec (blkId : rest) minIds = do
      mMinIds <- fmap textToMinId <$> undefined blkId -- TODO
      case mMinIds of
        Nothing -> do
          liftIO $ logWarning trce $
            mconcat
              [ "Failed to find ReverseInex for "
              , textShow (unBlockId blkId)
              , ". Deletion may take longer."
              ]
          pure (minIds, False)
        Just minIdDB -> do
          let minIds' = minIds <> minIdDB
          if isComplete minIds'
          then pure (minIds', True)
          else findMinIdsRec rest minIds'

    isComplete (MinIds m1 m2 m3 m4) = and [isJust m1, isJust m2, isJust m3, isJust m4]

completeMinId :: MonadIO m => BlockId -> MinIds -> ReaderT SqlBackend m MinIds
completeMinId blkId minIds = do
    mTxId <- queryMinRefId TxBlockId blkId
    case mTxId of
      Nothing -> pure mempty
      Just txId -> do
        mTxInId <- whenNothingQueryMinRefId (minTxInId minIds) TxInTxInId txId
        mTxOutId <- whenNothingQueryMinRefId (minTxOutId minIds) TxOutTxId txId
        mMaTxOutId <- case mTxOutId of
          Nothing -> pure Nothing
          Just txOutId -> whenNothingQueryMinRefId (minMaTxOutId minIds) MaTxOutTxOutId txOutId
        pure $ MinIds (Just txId) mTxInId mTxOutId mMaTxOutId

deleteTablesAfterBlockId :: MonadIO m => BlockId -> Maybe TxId -> Maybe TxInId -> Maybe TxOutId -> Maybe MaTxOutId -> ReaderT SqlBackend m ()
deleteTablesAfterBlockId blkId mtxId mtxInId mtxOutId mmaTxOutId = do
    deleteWhere [AdaPotsBlockId >=. blkId]
    deleteWhere [ReverseIndexBlockId >=. blkId]
    deleteWhere [EpochParamBlockId >=. blkId]
    deleteTablesAfterTxId mtxId mtxInId mtxOutId mmaTxOutId
    deleteWhere [BlockId >=. blkId]

deleteTablesAfterTxId :: MonadIO m => Maybe TxId -> Maybe TxInId -> Maybe TxOutId -> Maybe MaTxOutId -> ReaderT SqlBackend m ()
deleteTablesAfterTxId mtxId mtxInId mtxOutId mmaTxOutId = do
    whenJust mtxInId $ \txInId -> deleteWhere [TxInId >=. txInId]
    whenJust mmaTxOutId $ \maTxOutId -> deleteWhere [MaTxOutId >=. maTxOutId]
    whenJust mtxOutId $ \txOutId -> deleteWhere [TxOutId >=. txOutId]

    whenJust mtxId $ \txId -> do
      queryFirstAndDeleteAfter CollateralTxOutTxId txId
      queryFirstAndDeleteAfter CollateralTxInTxInId txId
      queryFirstAndDeleteAfter ReferenceTxInTxInId txId
      queryFirstAndDeleteAfter PoolRetireAnnouncedTxId txId
      queryFirstAndDeleteAfter StakeRegistrationTxId txId
      queryFirstAndDeleteAfter StakeDeregistrationTxId txId
      queryFirstAndDeleteAfter DelegationTxId txId
      queryFirstAndDeleteAfter TxMetadataTxId txId
      queryFirstAndDeleteAfter WithdrawalTxId txId
      queryFirstAndDeleteAfter TreasuryTxId txId
      queryFirstAndDeleteAfter ReserveTxId txId
      queryFirstAndDeleteAfter PotTransferTxId txId
      queryFirstAndDeleteAfter MaTxMintTxId txId
      queryFirstAndDeleteAfter RedeemerTxId txId
      queryFirstAndDeleteAfter ScriptTxId txId
      queryFirstAndDeleteAfter DatumTxId txId
      queryFirstAndDeleteAfter RedeemerDataTxId txId
      queryFirstAndDeleteAfter ExtraKeyWitnessTxId txId
      queryFirstAndDeleteAfter ParamProposalRegisteredTxId txId
      minPmr <- queryMinRefId PoolMetadataRefRegisteredTxId txId
      whenJust minPmr $ \pmrId -> do
        queryFirstAndDeleteAfter PoolOfflineDataPmrId pmrId
        queryFirstAndDeleteAfter PoolOfflineFetchErrorPmrId pmrId
        deleteWhere [PoolMetadataRefId >=. pmrId]
      minPoolUpdate <- queryMinRefId PoolUpdateRegisteredTxId txId
      whenJust minPoolUpdate $ \puid -> do
        queryFirstAndDeleteAfter PoolOwnerPoolUpdateId puid
        queryFirstAndDeleteAfter PoolRelayUpdateId puid
        deleteWhere [PoolUpdateId >=. puid]
      deleteWhere [TxId >=. txId]

queryFirstAndDeleteAfter
  :: forall m record field. (MonadIO m, PersistEntity record, PersistField field, PersistEntityBackend record ~ SqlBackend)
  => EntityField record field -> field -> ReaderT SqlBackend m ()
queryFirstAndDeleteAfter txIdField txId = do
    mRecordId <- queryMinRefId txIdField txId
    whenJust mRecordId $ \recordId ->
      deleteWhere [persistIdField @record >=. recordId]

-- | Delete a delisted pool if it exists. Returns 'True' if it did exist and has been
-- deleted and 'False' if it did not exist.
deleteDelistedPool :: MonadIO m => ByteString -> ReaderT SqlBackend m Bool
deleteDelistedPool poolHash = do
  keys <- selectKeysList [ DelistedPoolHashRaw ==. poolHash ] []
  mapM_ delete keys
  pure $ not (null keys)

whenNothingQueryMinRefId ::
     forall m record field. (MonadIO m, PersistEntity record, PersistField field)
  => Maybe (Key record)
  -> EntityField record field
  -> field
  -> ReaderT SqlBackend m (Maybe (Key record))
whenNothingQueryMinRefId mKey efield field = do
    case mKey of
      Just k -> pure $ Just k
      Nothing -> queryMinRefId efield field

-- | Delete a block if it exists. Returns 'True' if it did exist and has been
-- deleted and 'False' if it did not exist.
deleteBlock :: MonadIO m => Block -> ReaderT SqlBackend m Bool
deleteBlock block = do
  mBlockId <- listToMaybe <$> selectKeysList [ BlockHash ==. blockHash block ] []
  case mBlockId of
    Nothing -> pure False
    Just blockId -> do
      deleteBlocksBlockId nullTracer blockId
      pure True
