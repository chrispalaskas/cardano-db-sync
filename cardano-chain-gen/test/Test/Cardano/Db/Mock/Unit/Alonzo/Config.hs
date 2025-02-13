module Test.Cardano.Db.Mock.Unit.Alonzo.Config (
  defaultInsertConfig,
  insertConfig,
) where

import Cardano.DbSync.Config
import Cardano.DbSync.Config.Types
import Cardano.Prelude
import Data.Default.Class (Default (..))
import Test.Cardano.Db.Mock.Config
import Test.Tasty.HUnit (Assertion (), (@?=))
import Prelude ()

defaultInsertConfig :: Assertion
defaultInsertConfig = do
  cfg <- mkSyncNodeConfig alonzoConfigDir initCommandLineArgs
  dncInsertOptions cfg @?= def

insertConfig :: Assertion
insertConfig = do
  cfg <- mkSyncNodeConfig configDir initCommandLineArgs
  let expected =
        SyncInsertOptions
          { sioTxCBOR = TxCBORConfig False
          , sioTxOut = TxOutDisable
          , sioLedger = LedgerDisable
          , sioShelley = ShelleyDisable
          , sioRewards = RewardsConfig True
          , sioMultiAsset = MultiAssetDisable
          , sioMetadata = MetadataDisable
          , sioPlutus = PlutusDisable
          , sioGovernance = GovernanceConfig False
          , sioOffchainPoolData = OffchainPoolDataConfig False
          , sioJsonType = JsonTypeDisable
          , sioRemoveJsonbFromSchema = RemoveJsonbFromSchemaConfig False
          }

  dncInsertOptions cfg @?= expected
  where
    configDir = "config-alonzo-insert-options"
