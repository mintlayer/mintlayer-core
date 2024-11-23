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

export type AddressInfo = {
  wallet_id: number;
  account_id: string;
  index: number;
  address: string;
};

export type NewAccountResultType = {
  wallet_id: string;
  account_id: string;
  account_info: AccountType;
};

export type ToggleStakingResultType = {
  wallet_id: string;
  account_id: string;
  enabled: boolean;
};

export type ChainInfoType = {
  best_block_height: number;
  best_block_id: string;
  best_block_timestamp: {
    timestamp: number;
  };
  median_time: {
    timestamp: number;
  };
  is_initial_block_download: boolean;
};

export type ChainInfoEventPayloadType = {
  ChainInfo: ChainInfoType;
};

export type PeerDisconnected = {
  P2p: {
    PeerDisConnected: number;
  };
};

export type PeerConnected = {
  P2p: {
    PeerConnected: {
      id: number;
      services: number;
      address: string;
      inbound: boolean;
      user_agent: number[];
      software_version: {
        major: number;
        minor: number;
        patch: number;
      };
    };
  };
};

export type P2p = PeerConnected | PeerDisconnected;

export type Transaction = {
  V1: {
    version: number | null; // Assuming version can be a number or null
    flags: number; // Assuming flags is a number
    inputs: Input[]; // Array of Input objects
    outputs: Output[]; // Array of Output objects
  };
};

export type Input = {
  Utxo: {
    id: {
      Transaction: string; // Transaction ID as a string
    };
    index: number; // Index as a number
  };
};

export type Output = CreateStakePoolOutput | TransferOutput;

export type CreateStakePoolOutput = {
  CreateStakePool: [
    string,
    {
      pledge: {
        atoms: string;
      };
      staker: string;
      vrf_public_key: string;
      decomission_key: string;
      margin_ratio_per_thousand: string;
      cost_per_block: {
        atoms: string;
      };
    }
  ];
};

export type TransferOutput = {
  Transfer: [
    {
      Coin: {
        atoms: string;
      };
    },
    string
  ];
};

export type Signature = {
  Standard: {
    sighash_type: number; // Sighash type as a number
    raw_signature: number[]; // Raw signature as an array of numbers
  };
};

export type Tx = {
  transaction: Transaction; // Transaction object
  signatures: Signature[]; // Array of Signature objects
};

export type Data = {
  wallet_id: number; // Wallet ID as a number
  tx: Tx; // Transaction object
};
