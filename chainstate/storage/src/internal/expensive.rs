use super::*;

use crate::schema::{self as db};
use storage::MakeMapRef;

impl<B: storage::Backend> Store<B> {
    /// Dump raw database contents
    pub fn dump_raw(&self) -> crate::Result<storage::raw::StorageContents<Schema>> {
        self.0.dump_raw().map_err(crate::Error::from)
    }

    /// Collect and return all utxos from the storage
    pub fn read_utxo_set(&self) -> crate::Result<BTreeMap<UtxoOutPoint, Utxo>> {
        let db = self.transaction_ro()?;
        db.0.get::<db::DBUtxo, _>()
            .prefix_iter_decoded(&())
            .map(Iterator::collect)
            .map_err(crate::Error::from)
    }

    /// Collect and return all tip accounting data from storage
    pub fn read_pos_accounting_data_tip(&self) -> crate::Result<pos_accounting::PoSAccountingData> {
        let db = self.transaction_ro()?;

        let pool_data =
            db.0.get::<db::DBAccountingPoolDataTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_balances =
            db.0.get::<db::DBAccountingPoolBalancesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_data =
            db.0.get::<db::DBAccountingDelegationDataTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_balances =
            db.0.get::<db::DBAccountingDelegationBalancesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares =
            db.0.get::<db::DBAccountingPoolDelegationSharesTip, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }

    /// Collect and return all sealed accounting data from storage
    pub fn read_pos_accounting_data_sealed(
        &self,
    ) -> crate::Result<pos_accounting::PoSAccountingData> {
        let db = self.transaction_ro()?;

        let pool_data =
            db.0.get::<db::DBAccountingPoolDataSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_balances =
            db.0.get::<db::DBAccountingPoolBalancesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_data =
            db.0.get::<db::DBAccountingDelegationDataSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let delegation_balances =
            db.0.get::<db::DBAccountingDelegationBalancesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let pool_delegation_shares =
            db.0.get::<db::DBAccountingPoolDelegationSharesSealed, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        Ok(pos_accounting::PoSAccountingData {
            pool_data,
            pool_balances,
            pool_delegation_shares,
            delegation_balances,
            delegation_data,
        })
    }

    pub fn read_tokens_accounting_data(
        &self,
    ) -> crate::Result<tokens_accounting::TokensAccountingData> {
        let db = self.transaction_ro()?;

        let token_data =
            db.0.get::<db::DBTokensData, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        let circulating_supply =
            db.0.get::<db::DBTokensCirculatingSupply, _>()
                .prefix_iter_decoded(&())?
                .collect::<BTreeMap<_, _>>();

        Ok(tokens_accounting::TokensAccountingData {
            token_data,
            circulating_supply,
        })
    }
}
