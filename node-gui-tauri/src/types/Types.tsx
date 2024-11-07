export type RpcAmountOutType = {
  atoms: number;
  decimal: number;
};

export type RpcAddressType = {
  address: string;
  _phantom: string;
};

export type BalanceType = {
  coins: RpcAmountOutType;
  tokens: Record<string, RpcAmountOutType>;
};
export type PoolInfoType = {
  pool_id: string;
  pledge: RpcAmountOutType;
  balance: RpcAmountOutType;
  height: number;
  block_timestamp: { timestamp: number };
  vrf_public_key: string;
  staker: string;
  margin_ratio_per_thousand: number;
  cost_per_block: RpcAmountOutType;
};

export type AccountType = {
  name: string;
  addresses: Record<string, string>;
  staking_enabled: boolean;
  balance: BalanceType;
  staking_balance: Record<string, PoolInfoType>;
  delegations_balance: Record<string, [pool_id: string, amount: AmountType]>;
  transaction_list: TransactionType;
};

export type AmountType = {
  atoms: string;
};

export type TxType =
  | { Received: { amount: AmountType } }
  | { Redeposit: {} }
  | { Sent: { amount: AmountType } }
  | { Other: {} };

export type TxState =
  | {
      Confirmed: {
        height: number;
        timestamp: { timestamp: number };
        someValue: number;
      };
    }
  | { InMempool: { someValue: number } }
  | { Conflicted: { id: string } }
  | { Inactive: { someValue: number } }
  | { Abandoned: {} };

export type TransactionInfoType = {
  txid: string;
  tx_type: TxType;
  timestamp: { timestamp: number };
  state: TxState;
};

export type TransactionType = {
  count: number;
  skip: number;
  total: number;
  txs: TransactionInfoType[];
};

export type WalletInfo = {
  wallet_id: string;
  path: string;
  encryption: string;
  accounts: Record<string, AccountType>;
  best_block: [string, number];
  wallet_type: string;
};
