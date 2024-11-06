export type WalletType = {
  wallet_id: string;
  address: string;
  accounts: { account_id: string }[];
};

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
  amount: { atoms: string };
};

export type TxType =
  | { type: "Redeposit" }
  | { type: "Received"; amount: AmountType }
  | { type: "Sent"; amount: AmountType }
  | { type: "Other" };

export type TxState =
  | {
      type: "Confirmed";
      height: number;
      timestamp: { timestamp: number };
      someValue: number;
    }
  | { type: "InMempool"; someValue: number }
  | { type: "Conflicted"; id: string }
  | { type: "Inactive"; someValue: number }
  | { type: "Abandoned" };

export type TransactionInfoType = {
  txid: string;
  tx_type: TxType;
  timestamp: number;
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
