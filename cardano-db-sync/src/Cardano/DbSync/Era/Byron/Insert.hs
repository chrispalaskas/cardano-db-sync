{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# OPTIONS_GHC -Wno-unused-do-bind #-}

module Cardano.DbSync.Era.Byron.Insert (
  insertByronBlock,
) where

import Cardano.BM.Trace (Trace, logDebug, logInfo)
import Cardano.Binary (serialize')
import qualified Cardano.Chain.Block as Byron hiding (blockHash)
import qualified Cardano.Chain.Common as Byron
import qualified Cardano.Chain.UTxO as Byron
import qualified Cardano.Chain.Update as Byron hiding (protocolVersion)
import qualified Cardano.Crypto as Crypto (serializeCborHash)
import Cardano.Db (DbLovelace (..))
import qualified Cardano.Db as DB
import Cardano.DbSync.Api
import Cardano.DbSync.AppT (App, SyncEnv (..), SyncOptions (..), askTrace, dbQueryToApp)
import Cardano.DbSync.Cache (
  insertBlockAndCache,
  queryPrevBlockWithCache,
 )
import Cardano.DbSync.Cache.Epoch (writeEpochBlockDiffToCache)
import Cardano.DbSync.Cache.Types (CacheStatus (..), EpochBlockDiff (..))
import qualified Cardano.DbSync.Era.Byron.Util as Byron
import Cardano.DbSync.Era.Util (liftLookupFail)
import Cardano.DbSync.Error
import Cardano.DbSync.Error.Types (SyncInvariant (..), SyncNodeError (..))
import Cardano.DbSync.Types
import Cardano.DbSync.Util
import Cardano.Prelude
import Cardano.Slotting.Slot (EpochNo (..), EpochSize (..))
import Control.Monad.Trans.Except.Extra (firstExceptT)
import qualified Data.ByteString.Char8 as BS
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import Ouroboros.Consensus.Byron.Ledger (ByronBlock (..))

-- Trivial local data type for use in place of a tuple.
data ValueFee = ValueFee
  { vfValue :: !DbLovelace
  , vfFee :: !DbLovelace
  }

insertByronBlock ::
  Bool ->
  ByronBlock ->
  SlotDetails ->
  App (Either SyncNodeError ())
insertByronBlock firstBlockOfEpoch blk details = do
  res <-
    case byronBlockRaw blk of
      Byron.ABOBBlock ablk -> insertABlock firstBlockOfEpoch ablk details
      Byron.ABOBBoundary abblk -> insertABOBBoundary abblk details
  -- Serializing things during syncing can drastically slow down full sync
  -- times (ie 10x or more).
  when (getSyncStatus details == SyncFollowing) $
    dbQueryToApp DB.transactionCommit
  pure res

insertABOBBoundary ::
  Byron.ABoundaryBlock ByteString ->
  SlotDetails ->
  App (Either SyncNodeError ())
insertABOBBoundary blk details = do
  -- Will not get called in the OBFT part of the Byron era.
  pbid <- queryPrevBlockWithCache "insertABOBBoundary" (Byron.ebbPrevHash blk)
  let epochNo = unEpochNo $ sdEpochNo details
  slid <-
    dbQueryToApp . DB.insertSlotLeader $
      DB.SlotLeader
        { DB.slotLeaderHash = BS.replicate 28 '\0'
        , DB.slotLeaderPoolHashId = Nothing
        , DB.slotLeaderDescription = "Epoch boundary slot leader"
        }
  blkId <-
    insertBlockAndCache $
      DB.Block
        { DB.blockHash = Byron.unHeaderHash $ Byron.boundaryHashAnnotated blk
        , DB.blockEpochNo = Just epochNo
        , -- No slotNo for a boundary block
          DB.blockSlotNo = Nothing
        , DB.blockEpochSlotNo = Nothing
        , DB.blockBlockNo = Nothing
        , DB.blockPreviousId = Just pbid
        , DB.blockSlotLeaderId = slid
        , DB.blockSize = fromIntegral $ Byron.boundaryBlockLength blk
        , DB.blockTime = sdSlotTime details
        , DB.blockTxCount = 0
        , -- EBBs do not seem to have protocol version fields, so set this to '0'.
          DB.blockProtoMajor = 0
        , DB.blockProtoMinor = 0
        , -- Shelley specific
          DB.blockVrfKey = Nothing
        , DB.blockOpCert = Nothing
        , DB.blockOpCertCounter = Nothing
        }
  syncEnv <- ask
  tracer <- askTrace
  -- now that we've inserted the Block and all it's txs lets cache what we'll need
  -- when we later update the epoch values.
  -- If have --dissable-epoch && --dissable-cache then no need to cache data.
  when (soptEpochAndCacheEnabled $ envOptions syncEnv) $
    runOrThrowApp tracer $
      writeEpochBlockDiffToCache
        EpochBlockDiff
          { ebdBlockId = blkId
          , ebdFees = 0
          , ebdOutSum = 0
          , ebdTxCount = 0
          , ebdEpochNo = epochNo
          , ebdTime = sdSlotTime details
          }
  liftIO $
    logInfo tracer $
      Text.concat
        [ "insertABOBBoundary: epoch "
        , textShow (Byron.boundaryEpoch $ Byron.boundaryHeader blk)
        , ", hash "
        , Byron.renderAbstractHash (Byron.boundaryHashAnnotated blk)
        ]
  pure $ Right ()

insertABlock ::
  Bool ->
  Byron.ABlock ByteString ->
  SlotDetails ->
  App (Either SyncNodeError ())
insertABlock firstBlockOfEpoch blk details = do
  pbid <- queryPrevBlockWithCache "insertABlock" (Byron.blockPreviousHash blk)
  slid <- dbQueryToApp . DB.insertSlotLeader $ Byron.mkSlotLeader blk
  let txs = Byron.blockPayload blk
  blkId <-
    insertBlockAndCache $
      DB.Block
        { DB.blockHash = Byron.blockHash blk
        , DB.blockEpochNo = Just $ unEpochNo (sdEpochNo details)
        , DB.blockSlotNo = Just $ Byron.slotNumber blk
        , DB.blockEpochSlotNo = Just $ unEpochSlot (sdEpochSlot details)
        , DB.blockBlockNo = Just $ Byron.blockNumber blk
        , DB.blockPreviousId = Just pbid
        , DB.blockSlotLeaderId = slid
        , DB.blockSize = fromIntegral $ Byron.blockLength blk
        , DB.blockTime = sdSlotTime details
        , DB.blockTxCount = fromIntegral $ length txs
        , DB.blockProtoMajor = Byron.pvMajor (Byron.protocolVersion blk)
        , DB.blockProtoMinor = Byron.pvMinor (Byron.protocolVersion blk)
        , -- Shelley specific
          DB.blockVrfKey = Nothing
        , DB.blockOpCert = Nothing
        , DB.blockOpCertCounter = Nothing
        }

  txFees <- zipWithM (insertByronTx blkId) (Byron.blockPayload blk) [0 ..]
  let byronTxOutValues = concatMap (toList . (\tx -> map Byron.txOutValue (Byron.txOutputs $ Byron.taTx tx))) txs
      outSum = sum $ map Byron.lovelaceToInteger byronTxOutValues

  syncEnv <- ask
  tracer <- askTrace

  -- now that we've inserted the Block and all it's txs lets cache what we'll need
  -- when we later update the epoch values.
  -- If have --dissable-epoch && --dissable-cache then no need to cache data.
  when (soptEpochAndCacheEnabled $ envOptions syncEnv) $ do
    cacheResult <-
      writeEpochBlockDiffToCache
        EpochBlockDiff
          { ebdBlockId = blkId
          , ebdFees = sum txFees
          , ebdOutSum = fromIntegral outSum
          , ebdTxCount = fromIntegral $ length txs
          , ebdEpochNo = unEpochNo (sdEpochNo details)
          , ebdTime = sdSlotTime details
          }
    handleAndLogError tracer cacheResult

  let epoch = unEpochNo (sdEpochNo details)
      slotWithinEpoch = unEpochSlot (sdEpochSlot details)
      followingClosely = getSyncStatus details == SyncFollowing

  when (followingClosely && slotWithinEpoch /= 0 && Byron.blockNumber blk `mod` 20 == 0) $ do
    liftIO $
      logInfo tracer $
        mconcat
          [ "insertByronBlock: continuing epoch "
          , textShow epoch
          , " (slot "
          , textShow slotWithinEpoch
          , "/"
          , textShow (unEpochSize $ sdEpochSize details)
          , ")"
          ]
  liftIO $
    logger followingClosely tracer $
      mconcat
        [ "insertByronBlock: epoch "
        , textShow (unEpochNo $ sdEpochNo details)
        , ", slot "
        , textShow (Byron.slotNumber blk)
        , ", block "
        , textShow (Byron.blockNumber blk)
        , ", hash "
        , renderByteArray (Byron.blockHash blk)
        ]
  pure $ Right ()
  where
    logger :: Bool -> Trace IO a -> a -> IO ()
    logger followingClosely
      | firstBlockOfEpoch = logInfo
      | followingClosely = logInfo
      | Byron.blockNumber blk `mod` 1000 == 0 = logInfo
      | otherwise = logDebug

insertByronTx ::
  DB.BlockId ->
  Byron.TxAux ->
  Word64 ->
  App Word64
insertByronTx blkId tx blockIndex = do
  disInOut <- getDisableInOutState
  if disInOut
    then do
      void . dbQueryToApp . DB.insertTx $
        DB.Tx
          { DB.txHash = Byron.unTxHash $ Crypto.serializeCborHash (Byron.taTx tx)
          , DB.txBlockId = blkId
          , DB.txBlockIndex = blockIndex
          , DB.txOutSum = DbLovelace 0
          , DB.txFee = DbLovelace 0
          , DB.txDeposit = Nothing -- Byron does not have deposits/refunds
          -- Would be really nice to have a way to get the transaction size
          -- without re-serializing it.
          , DB.txSize = fromIntegral $ BS.length (serialize' $ Byron.taTx tx)
          , DB.txInvalidHereafter = Nothing
          , DB.txInvalidBefore = Nothing
          , DB.txValidContract = True
          , DB.txScriptSize = 0
          }
      pure 0
    else insertByronTx' blkId tx blockIndex

insertByronTx' ::
  DB.BlockId ->
  Byron.TxAux ->
  Word64 ->
  App Word64
insertByronTx' blkId tx blockIndex = do
  tracer <- askTrace
  resolvedInputs <- mapM resolveTxInputs (toList $ Byron.txInputs (Byron.taTx tx))
  valFee <-
    runOrThrowApp tracer $
      runExceptT $
        firstExceptT annotateTx $
          ExceptT $
            pure (calculateTxFee (Byron.taTx tx) resolvedInputs)
  txId <-
    dbQueryToApp . DB.insertTx $
      DB.Tx
        { DB.txHash = Byron.unTxHash $ Crypto.serializeCborHash (Byron.taTx tx)
        , DB.txBlockId = blkId
        , DB.txBlockIndex = blockIndex
        , DB.txOutSum = vfValue valFee
        , DB.txFee = vfFee valFee
        , DB.txDeposit = Just 0 -- Byron does not have deposits/refunds
        -- Would be really nice to have a way to get the transaction size
        -- without re-serializing it.
        , DB.txSize = fromIntegral $ BS.length (serialize' $ Byron.taTx tx)
        , DB.txInvalidHereafter = Nothing
        , DB.txInvalidBefore = Nothing
        , DB.txValidContract = True
        , DB.txScriptSize = 0
        }
  -- Insert outputs for a transaction before inputs in case the inputs for this transaction
  -- references the output (not sure this can even happen).
  disInOut <- getDisableInOutState
  hasConsumedOrPruneTxOut <- getHasConsumedOrPruneTxOut
  zipWithM_ (insertTxOut hasConsumedOrPruneTxOut disInOut txId) [0 ..] (toList . Byron.txOutputs $ Byron.taTx tx)
  skipTxIn <- getSkipTxIn
  unless skipTxIn $
    mapM_ (insertTxIn txId) resolvedInputs
  whenConsumeOrPruneTxOut $
    dbQueryToApp $
      DB.updateListTxOutConsumedByTxId (prepUpdate <$> resolvedInputs)
  -- fees are being returned so we can sum them and put them in cache to use when updating epochs
  pure $ unDbLovelace $ vfFee valFee
  where
    annotateTx :: SyncNodeError -> SyncNodeError
    annotateTx ee =
      case ee of
        SNErrInvariant loc ei -> SNErrInvariant loc (annotateInvariantTx (Byron.taTx tx) ei)
        _other -> ee

    prepUpdate (_, txId, txOutId, _) = (txOutId, txId)

insertTxOut ::
  Bool ->
  Bool ->
  DB.TxId ->
  Word32 ->
  Byron.TxOut ->
  App ()
insertTxOut hasConsumed bootStrap txId index txout =
  dbQueryToApp $
    DB.insertTxOutPlex hasConsumed bootStrap $
      DB.TxOut
        { DB.txOutTxId = txId
        , DB.txOutIndex = fromIntegral index
        , DB.txOutAddress = Text.decodeUtf8 $ Byron.addrToBase58 (Byron.txOutAddress txout)
        , DB.txOutAddressHasScript = False
        , DB.txOutPaymentCred = Nothing -- Byron does not have a payment credential.
        , DB.txOutStakeAddressId = Nothing -- Byron does not have a stake address.
        , DB.txOutValue = DbLovelace (Byron.unsafeGetLovelace $ Byron.txOutValue txout)
        , DB.txOutDataHash = Nothing
        , DB.txOutInlineDatumId = Nothing
        , DB.txOutReferenceScriptId = Nothing
        }

insertTxIn ::
  DB.TxId ->
  (Byron.TxIn, DB.TxId, DB.TxOutId, DbLovelace) ->
  App DB.TxInId
insertTxIn txInTxId (Byron.TxInUtxo _txHash inIndex, txOutTxId, _, _) = do
  dbQueryToApp . DB.insertTxIn $
    DB.TxIn
      { DB.txInTxInId = txInTxId
      , DB.txInTxOutId = txOutTxId
      , DB.txInTxOutIndex = fromIntegral inIndex
      , DB.txInRedeemerId = Nothing
      }

-- -----------------------------------------------------------------------------

resolveTxInputs :: Byron.TxIn -> App (Byron.TxIn, DB.TxId, DB.TxOutId, DbLovelace)
resolveTxInputs txIn@(Byron.TxInUtxo txHash index) = do
  res <- liftLookupFail "resolveInput" $ dbQueryToApp $ DB.queryTxOutIdValue (Byron.unTxHash txHash, fromIntegral index)
  pure $ convert res
  where
    convert :: (DB.TxId, DB.TxOutId, DbLovelace) -> (Byron.TxIn, DB.TxId, DB.TxOutId, DbLovelace)
    convert (txId, txOutId, lovelace) = (txIn, txId, txOutId, lovelace)

calculateTxFee :: Byron.Tx -> [(Byron.TxIn, DB.TxId, DB.TxOutId, DbLovelace)] -> Either SyncNodeError ValueFee
calculateTxFee tx resolvedInputs = do
  outval <- first (\e -> SNErrDefault $ "calculateTxFee: " <> textShow e) output
  when (null resolvedInputs) $
    Left $
      SNErrDefault "calculateTxFee: List of transaction inputs is zero."
  let inval = sum $ map (unDbLovelace . forth4) resolvedInputs
  if inval < outval
    then Left $ SNErrInvariant "calculateTxFee" $ EInvInOut inval outval
    else Right $ ValueFee (DbLovelace outval) (DbLovelace $ inval - outval)
  where
    output :: Either Byron.LovelaceError Word64
    output =
      Byron.unsafeGetLovelace
        <$> Byron.sumLovelace (map Byron.txOutValue $ Byron.txOutputs tx)
