{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE NoImplicitPrelude #-}

module Cardano.DbSync.Era.Universal.Insert.Tx (
  insertTx,
  insertTxOut,
)
where

import Cardano.BM.Trace (Trace)
import Cardano.Db (DbLovelace (..), DbWord64 (..))
import qualified Cardano.Db as DB
import Cardano.DbSync.Api
import Cardano.DbSync.Api.Types (InsertOptions (..), SyncEnv (..))
import Cardano.DbSync.Cache.Types (CacheStatus (..))
import Cardano.DbSync.Config.Types (MetadataConfig (..), MultiAssetConfig (..), PlutusConfig (..), isPlutusModeActive, isShelleyModeActive)
import qualified Cardano.DbSync.Era.Shelley.Generic as Generic
import Cardano.DbSync.Era.Shelley.Generic.Metadata (TxMetadataValue (..), metadataValueToJsonNoSchema)
import Cardano.DbSync.Era.Universal.Insert.Certificate (insertCertificate)
import Cardano.DbSync.Era.Universal.Insert.GovAction (
  insertGovActionProposal,
  insertParamProposal,
  insertVotingProcedures,
 )
import Cardano.DbSync.Era.Universal.Insert.Grouped
import Cardano.DbSync.Era.Universal.Insert.Other (
  insertDatum,
  insertExtraKeyWitness,
  insertMultiAsset,
  insertRedeemer,
  insertScript,
  insertScriptWithWhitelist,
  insertStakeAddressRefIfMissing,
  insertWithdrawals,
 )
import Cardano.DbSync.Era.Universal.Insert.Pool (IsPoolMember)
import Cardano.DbSync.Era.Util (liftLookupFail, safeDecodeToJson)
import Cardano.DbSync.Error
import Cardano.DbSync.Ledger.Types (ApplyResult (..), getGovExpiresAt, lookupDepositsMap)
import Cardano.DbSync.Util
import Cardano.DbSync.Util.Cbor (serialiseTxMetadataToCbor)
import Cardano.DbSync.Util.Whitelist (isPlutusScriptHashesInWhitelist, plutusMultiAssetWhitelistCheck, shelleyStkAddrWhitelistCheckWithAddr)
import Cardano.Ledger.BaseTypes
import Cardano.Ledger.Coin (Coin (..))
import Cardano.Ledger.Mary.Value (AssetName (..), MultiAsset (..), PolicyID (..))
import Cardano.Prelude
import Control.Monad.Extra (mapMaybeM)
import Control.Monad.Trans.Control (MonadBaseControl)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.ByteString.Short (ShortByteString)
import qualified Data.Map.Strict as Map
import Database.Persist.Sql (SqlBackend)
import Ouroboros.Consensus.Cardano.Block (StandardCrypto)

--------------------------------------------------------------------------------------
-- INSERT TX
--------------------------------------------------------------------------------------
insertTx ::
  (MonadBaseControl IO m, MonadIO m) =>
  SyncEnv ->
  IsPoolMember ->
  DB.BlockId ->
  EpochNo ->
  SlotNo ->
  ApplyResult ->
  Word64 ->
  Generic.Tx ->
  BlockGroupedData ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) BlockGroupedData
insertTx syncEnv isMember blkId epochNo slotNo applyResult blockIndex tx grouped = do
  let !txHash = Generic.txHash tx
  let !mdeposits = if not (Generic.txValidContract tx) then Just (Coin 0) else lookupDepositsMap txHash (apDepositsMap applyResult)
  let !outSum = fromIntegral $ unCoin $ Generic.txOutSum tx
      !withdrawalSum = fromIntegral $ unCoin $ Generic.txWithdrawalSum tx
      hasConsumed = getHasConsumedOrPruneTxOut syncEnv

  disInOut <- liftIO $ getDisableInOutState syncEnv
  -- In some txs and with specific configuration we may be able to find necessary data within the tx body.
  -- In these cases we can avoid expensive queries.
  (resolvedInputs, resolvedFees', resolvedDeposits) <- case (disInOut, mdeposits, unCoin <$> Generic.txFees tx) of
    (True, _, _) -> pure ([], 0, unCoin <$> mdeposits)
    (_, Just deposits, Just fees) -> do
      (resolvedInputs, _) <- splitLast <$> mapM (resolveTxInputs syncEnv hasConsumed False (fst <$> groupedTxOut grouped)) (Generic.txInputs tx)
      pure (resolvedInputs, fees, Just (unCoin deposits))
    (_, Nothing, Just fees) -> do
      (resolvedInputs, amounts) <- splitLast <$> mapM (resolveTxInputs syncEnv hasConsumed False (fst <$> groupedTxOut grouped)) (Generic.txInputs tx)
      if any isNothing amounts
        then pure (resolvedInputs, fees, Nothing)
        else
          let !inSum = sum $ map unDbLovelace $ catMaybes amounts
           in pure (resolvedInputs, fees, Just $ fromIntegral (inSum + withdrawalSum) - fromIntegral outSum - fromIntegral fees)
    -- Nothing in fees means a phase 2 failure
    (_, _, Nothing) -> do
      (resolvedInsFull, amounts) <- splitLast <$> mapM (resolveTxInputs syncEnv hasConsumed True (fst <$> groupedTxOut grouped)) (Generic.txInputs tx)
      let !inSum = sum $ map unDbLovelace $ catMaybes amounts
          !diffSum = if inSum >= outSum then inSum - outSum else 0
          !fees = maybe diffSum (fromIntegral . unCoin) (Generic.txFees tx)
      pure (resolvedInsFull, fromIntegral fees, Just 0)
  let resolvedFees = fromIntegral resolvedFees'
  -- Insert transaction and get txId from the DB.
  !txId <-
    lift
      . DB.insertTx
      $ DB.Tx
        { DB.txHash = txHash
        , DB.txBlockId = blkId
        , DB.txBlockIndex = blockIndex
        , DB.txOutSum = DB.DbLovelace outSum
        , DB.txFee = DB.DbLovelace resolvedFees
        , DB.txDeposit = fromIntegral <$> resolvedDeposits
        , DB.txSize = Generic.txSize tx
        , DB.txInvalidBefore = DbWord64 . unSlotNo <$> Generic.txInvalidBefore tx
        , DB.txInvalidHereafter = DbWord64 . unSlotNo <$> Generic.txInvalidHereafter tx
        , DB.txValidContract = Generic.txValidContract tx
        , DB.txScriptSize = sum $ Generic.txScriptSizes tx
        }

  if not (Generic.txValidContract tx)
    then do
      !txOutsGrouped <- do
        if isplutusMultiAssetInWhitelist
          then mapMaybeM (insertTxOut syncEnv cache iopts (txId, txHash)) txOuts
          else pure mempty

      let !txIns = map (prepareTxIn txId Map.empty) resolvedInputs
      -- There is a custom semigroup instance for BlockGroupedData which uses addition for the values `fees` and `outSum`.
      -- Same happens bellow on last line of this function.
      pure (grouped <> BlockGroupedData txIns txOutsGrouped [] [] resolvedFees outSum)
    else do
      -- The following operations only happen if the script passes stage 2 validation (or the tx has
      -- no script).
      !txOutsGrouped <- do
        if isplutusMultiAssetInWhitelist
          then mapMaybeM (insertTxOut syncEnv cache iopts (txId, txHash)) txOuts
          else pure mempty

      !redeemers <-
        Map.fromList
          <$> whenFalseMempty
            (isPlutusModeActive $ ioPlutus iopts)
            (mapM (insertRedeemer syncEnv disInOut (fst <$> groupedTxOut grouped) txId) (Generic.txRedeemer tx))

      when (isPlutusModeActive $ ioPlutus iopts) $ do
        mapM_ (insertDatum syncEnv cache txId) (Generic.txData tx)
        mapM_ (insertCollateralTxIn tracer txId) (Generic.txCollateralInputs tx)
        mapM_ (insertReferenceTxIn tracer txId) (Generic.txReferenceInputs tx)
        mapM_ (insertExtraKeyWitness txId) $ Generic.txExtraKeyWitnesses tx
        mapM_ (lift . insertScriptWithWhitelist syncEnv txId) $ Generic.txScripts tx
        mapM_ (insertCollateralTxOut syncEnv cache (txId, txHash)) (Generic.txCollateralOutputs tx)

      txMetadata <- do
        case ioMetadata iopts of
          MetadataDisable -> pure mempty
          MetadataEnable -> prepareTxMetadata syncEnv Nothing txId (Generic.txMetadata tx)
          MetadataKeys whitelist -> prepareTxMetadata syncEnv (Just whitelist) txId (Generic.txMetadata tx)

      mapM_
        (insertCertificate syncEnv isMember mDeposits blkId txId epochNo slotNo redeemers)
        $ Generic.txCertificates tx

      when (isShelleyModeActive $ ioShelley iopts) $ do
        mapM_ (insertWithdrawals syncEnv cache txId redeemers) $ Generic.txWithdrawals tx
        mapM_ (lift . insertParamProposal blkId txId) $ Generic.txParamProposal tx

      maTxMint <-
        case ioMultiAssets iopts of
          MultiAssetDisable -> pure mempty
          MultiAssetEnable -> insertMaTxMint cache Nothing txId $ Generic.txMint tx
          MultiAssetPolicies whitelist -> insertMaTxMint cache (Just whitelist) txId $ Generic.txMint tx

      when (ioGov iopts) $ do
        mapM_ (insertGovActionProposal syncEnv blkId txId (getGovExpiresAt applyResult epochNo) (apCommittee applyResult)) $ zip [0 ..] (Generic.txProposalProcedure tx)
        mapM_ (insertVotingProcedures syncEnv blkId txId (Generic.txProposalProcedure tx)) (Generic.txVotingProcedure tx)

      let !txIns = map (prepareTxIn txId redeemers) resolvedInputs
      pure (grouped <> BlockGroupedData txIns txOutsGrouped txMetadata maTxMint resolvedFees outSum)
  where
    txOuts = Generic.txOutputs tx
    txMints = Generic.txMint tx
    tracer = getTrace syncEnv
    cache = envCache syncEnv
    iopts = getInsertOptions syncEnv
    mDeposits = maybeFromStrict $ apDeposits applyResult
    isplutusMultiAssetInWhitelist = plutusMultiAssetWhitelistCheck syncEnv txMints txOuts

--------------------------------------------------------------------------------------
-- INSERT TXOUT
--------------------------------------------------------------------------------------
insertTxOut ::
  (MonadBaseControl IO m, MonadIO m) =>
  SyncEnv ->
  CacheStatus ->
  InsertOptions ->
  (DB.TxId, ByteString) ->
  Generic.TxOut ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) (Maybe (ExtendedTxOut, [MissingMaTxOut]))
insertTxOut syncEnv cache iopts (txId, txHash) (Generic.TxOut index addr value maMap mScript dt) =
  case ioPlutus iopts of
    PlutusDisable -> buildExtendedTxOutPart2 Nothing Nothing
    _other -> buildExtendedTxOutPart1
  where
    buildExtendedTxOutPart1 ::
      (MonadBaseControl IO m, MonadIO m) =>
      ExceptT SyncNodeError (ReaderT SqlBackend m) (Maybe (ExtendedTxOut, [MissingMaTxOut]))
    buildExtendedTxOutPart1 = do
      mDatumId <- Generic.whenInlineDatum dt $ insertDatum syncEnv cache txId
      mScriptId <- case mScript of
        Just script -> lift $ Just <$> insertScript syncEnv txId script
        Nothing -> pure Nothing
      buildExtendedTxOutPart2 mDatumId mScriptId

    buildExtendedTxOutPart2 ::
      (MonadBaseControl IO m, MonadIO m) =>
      Maybe DB.DatumId ->
      Maybe DB.ScriptId ->
      ExceptT SyncNodeError (ReaderT SqlBackend m) (Maybe (ExtendedTxOut, [MissingMaTxOut]))
    buildExtendedTxOutPart2 mDatumId mScriptId = do
      mSaId <- lift $ insertStakeAddressRefIfMissing syncEnv cache addr
      let !txOut =
            DB.TxOut
              { DB.txOutTxId = txId
              , DB.txOutIndex = index
              , DB.txOutAddress = Generic.renderAddress addr
              , DB.txOutAddressHasScript = hasScript
              , DB.txOutPaymentCred = Generic.maybePaymentCred addr
              , DB.txOutStakeAddressId = mSaId
              , DB.txOutValue = Generic.coinToDbLovelace value
              , DB.txOutDataHash = Generic.dataHashToBytes <$> Generic.getTxOutDatumHash dt
              , DB.txOutInlineDatumId = mDatumId
              , DB.txOutReferenceScriptId = mScriptId
              }
      let !eutxo = ExtendedTxOut txHash txOut
      case ioMultiAssets iopts of
        MultiAssetDisable -> pure $ Just (eutxo, mempty)
        MultiAssetEnable -> do
          !maTxOuts <- insertMaTxOuts cache Nothing maMap
          pure $ Just (eutxo, maTxOuts)
        MultiAssetPolicies whitelist -> do
          !maTxOuts <- insertMaTxOuts cache (Just whitelist) maMap
          pure $ Just (eutxo, maTxOuts)

    hasScript :: Bool
    hasScript = maybe False Generic.hasCredScript (Generic.getPaymentCred addr)

prepareTxMetadata ::
  (MonadIO m) =>
  SyncEnv ->
  Maybe (NonEmpty Word) ->
  DB.TxId ->
  Maybe (Map Word64 TxMetadataValue) ->
  m [DB.TxMetadata]
prepareTxMetadata syncEnv mWhitelist txId mmetadata =
  case mmetadata of
    Nothing -> pure []
    Just metadata -> do
      whitelistAndPrepare $ Map.toList metadata
  where
    whitelistAndPrepare ::
      (MonadIO m) =>
      [(Word64, TxMetadataValue)] ->
      m [DB.TxMetadata]
    whitelistAndPrepare metadataList =
      case mWhitelist of
        -- if we have any metadata key in the whitelist then keep all metadata
        -- otherwise discard all metadata.
        Just whitelist ->
          if isAnyInWhitelist whitelist metadataList
            then mapM mkDbTxMetadata metadataList
            else pure []
        -- not using a whitelist, keep all metadata
        Nothing -> mapM mkDbTxMetadata metadataList

    isAnyInWhitelist ::
      NonEmpty Word ->
      [(Word64, TxMetadataValue)] ->
      Bool
    isAnyInWhitelist whitelist metaDataList = do
      let results = map (\(key, _) -> fromIntegral key `elem` whitelist) metaDataList
      or results

    mkDbTxMetadata ::
      (MonadIO m) =>
      (Word64, TxMetadataValue) ->
      m DB.TxMetadata
    mkDbTxMetadata (key, md) = do
      let jsonbs = LBS.toStrict $ Aeson.encode (metadataValueToJsonNoSchema md)
          singleKeyCBORMetadata = serialiseTxMetadataToCbor $ Map.singleton key md
      mjson <- safeDecodeToJson syncEnv "prepareTxMetadata: Column 'json' in table 'metadata' " jsonbs
      pure $
        DB.TxMetadata
          { DB.txMetadataKey = DbWord64 key
          , DB.txMetadataJson = mjson
          , DB.txMetadataBytes = singleKeyCBORMetadata
          , DB.txMetadataTxId = txId
          }

--------------------------------------------------------------------------------------
-- INSERT MULTI ASSET
--------------------------------------------------------------------------------------
insertMaTxMint ::
  (MonadBaseControl IO m, MonadIO m) =>
  CacheStatus ->
  Maybe (NonEmpty ShortByteString) ->
  DB.TxId ->
  MultiAsset StandardCrypto ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) [DB.MaTxMint]
insertMaTxMint cache mWhitelist txId (MultiAsset mintMap) =
  concatMapM (lift . prepareOuter) $ Map.toList mintMap
  where
    prepareOuter ::
      (MonadBaseControl IO m, MonadIO m) =>
      (PolicyID StandardCrypto, Map AssetName Integer) ->
      ReaderT SqlBackend m [DB.MaTxMint]
    prepareOuter (policy, aMap) =
      mapMaybeM (prepareInner policy) $ Map.toList aMap

    prepareInner ::
      (MonadBaseControl IO m, MonadIO m) =>
      PolicyID StandardCrypto ->
      (AssetName, Integer) ->
      ReaderT SqlBackend m (Maybe DB.MaTxMint)
    prepareInner policy (aname, amount) = do
      maybeMaId <- insertMultiAsset cache mWhitelist policy aname
      pure $ case maybeMaId of
        Just maId ->
          Just $
            DB.MaTxMint
              { DB.maTxMintIdent = maId
              , DB.maTxMintQuantity = DB.integerToDbInt65 amount
              , DB.maTxMintTxId = txId
              }
        Nothing -> Nothing

insertMaTxOuts ::
  (MonadBaseControl IO m, MonadIO m) =>
  CacheStatus ->
  Maybe (NonEmpty ShortByteString) ->
  Map (PolicyID StandardCrypto) (Map AssetName Integer) ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) [MissingMaTxOut]
insertMaTxOuts cache mWhitelist maMap =
  concatMapM (lift . prepareOuter) $ Map.toList maMap
  where
    prepareOuter ::
      (MonadBaseControl IO m, MonadIO m) =>
      (PolicyID StandardCrypto, Map AssetName Integer) ->
      ReaderT SqlBackend m [MissingMaTxOut]
    prepareOuter (policy, aMap) =
      mapMaybeM (prepareInner policy) $ Map.toList aMap

    prepareInner ::
      (MonadBaseControl IO m, MonadIO m) =>
      PolicyID StandardCrypto ->
      (AssetName, Integer) ->
      ReaderT SqlBackend m (Maybe MissingMaTxOut)
    prepareInner policy (aname, amount) = do
      mMaId <- insertMultiAsset cache mWhitelist policy aname
      pure $ case mMaId of
        Just maId ->
          Just $
            MissingMaTxOut
              { mmtoIdent = maId
              , mmtoQuantity = DbWord64 (fromIntegral amount)
              }
        Nothing -> Nothing

insertCollateralTxOut ::
  (MonadBaseControl IO m, MonadIO m) =>
  SyncEnv ->
  CacheStatus ->
  (DB.TxId, ByteString) ->
  Generic.TxOut ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) ()
insertCollateralTxOut syncEnv cache (txId, _txHash) txout@(Generic.TxOut index addr value maMap mScript dt) = do
  -- check if shelley stake address is in the whitelist
  when (shelleyStkAddrWhitelistCheckWithAddr syncEnv addr) $ do
    -- check plutus script hash is in the whitelist
    if isPlutusScriptHashesInWhitelist syncEnv [txout]
      then insertColTxOutPart1
      else void $ insertColTxOutPart2 Nothing Nothing
  where
    insertColTxOutPart1 = do
      mDatumId <- Generic.whenInlineDatum dt $ insertDatum syncEnv cache txId
      mScriptId <- case mScript of
        Just script -> lift $ Just <$> insertScript syncEnv txId script
        Nothing -> pure Nothing
      insertColTxOutPart2 mDatumId mScriptId
      pure ()

    insertColTxOutPart2 mDatumId mScriptId = do
      mSaId <- lift $ insertStakeAddressRefIfMissing syncEnv cache addr
      _ <-
        lift
          . DB.insertCollateralTxOut
          $ DB.CollateralTxOut
            { DB.collateralTxOutTxId = txId
            , DB.collateralTxOutIndex = index
            , DB.collateralTxOutAddress = Generic.renderAddress addr
            , DB.collateralTxOutAddressHasScript = hasScript
            , DB.collateralTxOutPaymentCred = Generic.maybePaymentCred addr
            , DB.collateralTxOutStakeAddressId = mSaId
            , DB.collateralTxOutValue = Generic.coinToDbLovelace value
            , DB.collateralTxOutDataHash = Generic.dataHashToBytes <$> Generic.getTxOutDatumHash dt
            , DB.collateralTxOutMultiAssetsDescr = textShow maMap
            , DB.collateralTxOutInlineDatumId = mDatumId
            , DB.collateralTxOutReferenceScriptId = mScriptId
            }
      pure ()
    hasScript :: Bool
    hasScript = maybe False Generic.hasCredScript (Generic.getPaymentCred addr)

insertCollateralTxIn ::
  (MonadBaseControl IO m, MonadIO m) =>
  Trace IO Text ->
  DB.TxId ->
  Generic.TxIn ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) ()
insertCollateralTxIn _tracer txInId (Generic.TxIn txId index _) = do
  txOutId <- liftLookupFail "insertCollateralTxIn" $ DB.queryTxId txId
  void
    . lift
    . DB.insertCollateralTxIn
    $ DB.CollateralTxIn
      { DB.collateralTxInTxInId = txInId
      , DB.collateralTxInTxOutId = txOutId
      , DB.collateralTxInTxOutIndex = fromIntegral index
      }

insertReferenceTxIn ::
  (MonadBaseControl IO m, MonadIO m) =>
  Trace IO Text ->
  DB.TxId ->
  Generic.TxIn ->
  ExceptT SyncNodeError (ReaderT SqlBackend m) ()
insertReferenceTxIn _tracer txInId (Generic.TxIn txId index _) = do
  txOutId <- liftLookupFail "insertReferenceTxIn" $ DB.queryTxId txId
  void
    . lift
    . DB.insertReferenceTxIn
    $ DB.ReferenceTxIn
      { DB.referenceTxInTxInId = txInId
      , DB.referenceTxInTxOutId = txOutId
      , DB.referenceTxInTxOutIndex = fromIntegral index
      }

--------------------------------------------------------------------------------------
-- Prepare TX-IN
--------------------------------------------------------------------------------------
prepareTxIn ::
  DB.TxId ->
  Map Word64 DB.RedeemerId ->
  (Generic.TxIn, DB.TxId, Either Generic.TxIn DB.TxOutId) ->
  ExtendedTxIn
prepareTxIn txInId redeemers (txIn, txOutId, mTxOutId) =
  ExtendedTxIn
    { etiTxIn = txInDB
    , etiTxOutId = mTxOutId
    }
  where
    txInDB =
      DB.TxIn
        { DB.txInTxInId = txInId
        , DB.txInTxOutId = txOutId
        , DB.txInTxOutIndex = fromIntegral $ Generic.txInIndex txIn
        , DB.txInRedeemerId = mlookup (Generic.txInRedeemerIndex txIn) redeemers
        }
