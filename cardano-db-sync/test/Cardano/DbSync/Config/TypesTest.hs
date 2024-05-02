{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Cardano.DbSync.Config.TypesTest (tests) where

import Cardano.DbSync.Config.Types
import qualified Cardano.DbSync.Gen as Gen
import Cardano.Prelude
import qualified Data.Aeson as Aeson
import Data.Aeson.QQ.Simple (aesonQQ)
import Data.Default.Class (Default (..))
import Hedgehog
import qualified Hedgehog.Gen as Gen
import Prelude ()

tests :: IO Bool
tests =
  checkParallel $
    Group
      "Cardano.DbSync.Config.Types"
      [ ("SyncInsertConfig FromJSON", prop_syncInsertConfigFromJSON)
      , ("SyncInsertConfig roundtrip", prop_syncInsertConfigRoundtrip)
      , ("isTxEnabled", prop_isTxEnabled)
      , ("hasLedger", prop_hasLedger)
      , ("shouldUseLedger", prop_shouldUseLedger)
      , ("isShelleyEnabled", prop_isShelleyEnabled)
      , ("isMultiAssetModeActive", prop_isMultiAssetModeActive)
      , ("isMetadataModeActive", prop_isMetadataModeActive)
      , ("isPlutusModeActive", prop_isPlutusModeActive)
      ]

prop_syncInsertConfigFromJSON :: Property
prop_syncInsertConfigFromJSON = property $ do
  json <- forAll genDefaultJson

  Aeson.fromJSON json === Aeson.Success (def :: SyncInsertConfig)

prop_syncInsertConfigRoundtrip :: Property
prop_syncInsertConfigRoundtrip = property $ do
  cfg <- forAll Gen.syncInsertConfig

  let isSyncInsertConfig =
        case cfg of
          SyncInsertConfig _ -> True
          _ -> False

  cover 5 "full" (cfg == FullInsertOptions)
  cover 5 "only utxo" (cfg == OnlyUTxOInsertOptions)
  cover 5 "only gov" (cfg == OnlyGovInsertOptions)
  cover 5 "disable all" (cfg == DisableAllInsertOptions)
  cover 5 "config" isSyncInsertConfig

  tripping cfg Aeson.encode Aeson.decode

prop_isTxEnabled :: Property
prop_isTxEnabled = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let txOutCfg = sioTxOut cfg

  -- TxOut is enabled if it is not TxOutDisable
  isTxOutEnabled txOutCfg === (txOutCfg /= TxOutDisable)

prop_hasLedger :: Property
prop_hasLedger = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let ledgerCfg = sioLedger cfg

  -- Ledger is enabled if it is not LedgerDisable
  hasLedger ledgerCfg === (ledgerCfg /= LedgerDisable)

prop_shouldUseLedger :: Property
prop_shouldUseLedger = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let ledgerCfg = sioLedger cfg

  -- Ledger is enabled if it is not LedgerDisable
  shouldUseLedger ledgerCfg === (ledgerCfg == LedgerEnable)

prop_isShelleyEnabled :: Property
prop_isShelleyEnabled = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let shelleyCfg = sioShelley cfg

  -- Shelley is enabled if it is not ShelleyDisable
  isShelleyModeActive shelleyCfg === (shelleyCfg /= ShelleyDisable)

prop_isMultiAssetModeActive :: Property
prop_isMultiAssetModeActive = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let multiAssetCfg = sioMultiAsset cfg

  -- MultiAsset is enabled if it is not MultiAssetDisable
  isMultiAssetModeActive multiAssetCfg === (multiAssetCfg /= MultiAssetDisable)

prop_isMetadataModeActive :: Property
prop_isMetadataModeActive = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let metadataCfg = sioMetadata cfg

  -- Metadata is enabled if it is not MetadataDisable
  isMetadataModeActive metadataCfg === (metadataCfg /= MetadataDisable)

prop_isPlutusModeActive :: Property
prop_isPlutusModeActive = property $ do
  cfg <- forAll Gen.syncInsertOptions
  let plutusCfg = sioPlutus cfg

  -- Plutus is enabled if it is not PlutusDisable
  isPlutusModeActive plutusCfg === (plutusCfg /= PlutusDisable)

-- | Various JSON values that should generate the default config
genDefaultJson :: Gen Aeson.Value
genDefaultJson =
  Gen.element
    [ [aesonQQ|
        {
          "tx_out": {
            "value": "enable"
          },
          "ledger": "enable",
          "shelley": {
            "enable": true,
            "stake_addresses": null
          },
          "multi_asset": {
            "enable": true,
            "policies": null
          },
          "metadata": {
            "enable": true,
            "keys": null
          },
          "plutus": {
            "enable": true,
            "script_hashes": null
          },
          "governance": "enable",
          "offchain_pool_data": "enable",
          "json_type": "text"
        }
      |]
    , [aesonQQ|
        { }
      |]
    , [aesonQQ|
        {
          "tx_out": {
            "value": "enable"
          },
          "ledger": "enable",
          "shelley": {
            "enable": true
          },
          "multi_asset": {
            "enable": true
          },
          "metadata": {
            "enable": true
          },
          "plutus": {
            "enable": true
          },
          "governance": "enable",
          "offchain_pool_data": "enable",
          "json_type": "text"
        }
      |]
    ]
