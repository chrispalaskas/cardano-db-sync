{-# LANGUAGE OverloadedStrings #-}

module Cardano.DbSync.Util.Whitelist where

import Cardano.BM.Trace (logInfo)
import Cardano.DbSync.Api (getTrace)
import Cardano.DbSync.Api.Types (InsertOptions (..), SyncEnv (..), SyncOptions (..))
import Cardano.DbSync.Config.Types (MultiAssetConfig (..), PlutusConfig (..), ShelleyInsertConfig (..))
import qualified Cardano.DbSync.Era.Shelley.Generic as Generic
import Cardano.DbSync.Error (shortBsBase16Encode)
import qualified Cardano.Ledger.Address as Ledger
import qualified Cardano.Ledger.Credential as Ledger
import Cardano.Ledger.Crypto (StandardCrypto)
import Cardano.Ledger.Mary.Value (PolicyID (..))
import Cardano.Prelude (NonEmpty)
import Data.ByteString.Short (ShortByteString, toShort)
import Data.Map (keys)

-- check both whitelist but also checking plutus Maybes first
plutusMultiAssetWhitelistCheck :: SyncEnv -> [Generic.TxOut] -> Bool
plutusMultiAssetWhitelistCheck syncEnv txOuts =
  isPlutusScriptHashesInWhitelist syncEnv txOuts || isMAPoliciesInWhitelist syncEnv txOuts

isPlutusScriptHashesInWhitelist :: SyncEnv -> [Generic.TxOut] -> Bool
isPlutusScriptHashesInWhitelist syncEnv txOuts = do
  -- first check the config option
  case ioPlutus iopts of
    PlutusEnable -> True
    PlutusDisable -> False
    PlutusScripts plutusWhitelist -> plutuswhitelistCheck plutusWhitelist
  where
    iopts = soptInsertOptions $ envOptions syncEnv
    plutuswhitelistCheck :: NonEmpty ShortByteString -> Bool
    plutuswhitelistCheck whitelist =
      any (\txOut -> isScriptHashWhitelisted whitelist txOut || isAddressWhitelisted whitelist txOut) txOuts
    -- check if the script hash is in the whitelist
    isScriptHashWhitelisted :: NonEmpty ShortByteString -> Generic.TxOut -> Bool
    isScriptHashWhitelisted whitelist txOut =
      maybe False ((`elem` whitelist) . toShort . Generic.txScriptHash) (Generic.txOutScript txOut)
    -- check if the address is in the whitelist
    isAddressWhitelisted :: NonEmpty ShortByteString -> Generic.TxOut -> Bool
    isAddressWhitelisted whitelist txOut =
      maybe False ((`elem` whitelist) . toShort) (Generic.maybePaymentCred $ Generic.txOutAddress txOut)

isMAPoliciesInWhitelist :: SyncEnv -> [Generic.TxOut] -> Bool
isMAPoliciesInWhitelist syncEnv txOuts = do
  let iopts = soptInsertOptions $ envOptions syncEnv
  case ioMultiAssets iopts of
    MultiAssetEnable -> True
    MultiAssetDisable -> False
    MultiAssetPolicies multiAssetWhitelist ->
      or multiAssetwhitelistCheck
      where
        -- txOutMaValue is a Map and we want to check if any of the keys match our whitelist
        multiAssetwhitelistCheck :: [Bool]
        multiAssetwhitelistCheck =
          ( \txout ->
              any (checkMAValueMap multiAssetWhitelist) (keys $ Generic.txOutMaValue txout)
          )
            <$> txOuts

        checkMAValueMap :: NonEmpty ShortByteString -> PolicyID StandardCrypto -> Bool
        checkMAValueMap maWhitelist policyId =
          toShort (Generic.unScriptHash (policyID policyId)) `elem` maWhitelist

shelleyStkAddrWhitelistCheckWithAddr ::
  SyncEnv ->
  Ledger.Addr StandardCrypto ->
  Bool
shelleyStkAddrWhitelistCheckWithAddr syncEnv addr = do
  case addr of
    Ledger.AddrBootstrap {} -> False
    Ledger.Addr network _pcred stakeRef ->
      case stakeRef of
        Ledger.StakeRefBase cred -> shelleyStakeAddrWhitelistCheck syncEnv $ Ledger.RewardAcnt network cred
        Ledger.StakeRefPtr _ -> True
        Ledger.StakeRefNull -> True

shelleyCustomStakeWhitelistCheck :: SyncEnv -> Ledger.RewardAcnt StandardCrypto -> Bool
shelleyCustomStakeWhitelistCheck syncEnv rwdAcc = do
  case ioShelley iopts of
    ShelleyDisable -> True
    ShelleyEnable -> True
    ShelleyStakeAddrs shelleyWhitelist -> checkShelleyWhitelist shelleyWhitelist rwdAcc
  where
    iopts = soptInsertOptions $ envOptions syncEnv

shelleyStakeAddrWhitelistCheck :: SyncEnv -> Ledger.RewardAcnt StandardCrypto -> Bool
shelleyStakeAddrWhitelistCheck syncEnv rwdAcc = do
  case ioShelley iopts of
    ShelleyDisable -> False
    ShelleyEnable -> True
    ShelleyStakeAddrs shelleyWhitelist -> checkShelleyWhitelist shelleyWhitelist rwdAcc
  where
    iopts = soptInsertOptions $ envOptions syncEnv

-- | Check Shelley is enabled and if the stake address is in the whitelist
checkShelleyWhitelist :: NonEmpty ShortByteString -> Ledger.RewardAcnt StandardCrypto -> Bool
checkShelleyWhitelist shelleyWhitelist rwdAcc = do
  shortBsBase16Encode stakeAddress `elem` shelleyWhitelist
  where
    network = Ledger.getRwdNetwork rwdAcc
    rewardCred = Ledger.getRwdCred rwdAcc
    stakeAddress = Ledger.serialiseRewardAcnt (Ledger.RewardAcnt network rewardCred)
