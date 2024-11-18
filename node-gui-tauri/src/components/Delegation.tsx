import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { AiOutlineCopy } from "react-icons/ai";
import { AccountType, WalletInfo } from "../types/Types";
import { notify } from "../utils/util";
import { IoCloseSharp } from "react-icons/io5";

const Delegation = (props: {
  currentAccount: AccountType | undefined;
  currentAccountId: number;
  currentWallet: WalletInfo | undefined;
}) => {
  const delegations = [
    {
      delegation_address: "tdlg1reswefwe09fwefwef9wef",
      pool_address: "tpool1frwewsefwewefw09wef",
      delegation_balance: "320.0020342",
    },
    {
      delegation_address: "tdlg1reswefwe09fwefwef9wef",
      pool_address: "tpool1frwewsefwewefw09wef",
      delegation_balance: "320.0020342",
    },
    {
      delegation_address: "tdlg1reswefwe09fwefwef9wef",
      pool_address: "tpool1frwewsefwewefw09wef",
      delegation_balance: "320.0020342",
    },
  ];

  const [poolAddress, setPoolAddress] = useState("");
  const [delegationAddress, setDelegationAddress] = useState("");
  const [showDepositModal, setShowDepositModal] = useState(false);
  const [depositAmount, setDepositAmount] = useState(0);
  const [withdrawAmount, setWithdrawAmount] = useState(0);
  const [withdrawAddress, setWithdrawAddress] = useState("");
  const [currentDelegationId, setCurrentDelegationId] = useState("");
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  const handleDeposit = async () => {
    try {
      const result = await invoke("delegate_staking_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          account_id: props.currentAccountId,
          pool_id: poolAddress,
          delegation_amount: depositAmount,
        },
      });
      if (result) {
        console.log(result);
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };
  const handleWithdraw = async () => {
    try {
      const result = await invoke("send_delegation_to_address_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          account_id: props.currentAccountId,
          address: withdrawAddress,
          amount: withdrawAmount,
          delegation_id: currentDelegationId,
        },
      });
      if (result) {
        console.log(result);
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };

  const handleSelectAllAmount = () => {
    setWithdrawAmount(
      props.currentAccount?.staking_balance[poolAddress].balance.decimal
        ? props.currentAccount?.staking_balance[poolAddress].balance.decimal
        : 0
    );
  };

  const handleCreateDelegation = async () => {
    try {
      const result = await invoke("create_deletation_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          account_id: props.currentAccountId,
          pool_id: poolAddress,
          delegation_address: delegationAddress,
        },
      });
      if (result) {
        console.log(result);
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };
  return (
    <div className="container pt-0 p-4 shadow-1">
      {showDepositModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50">Deposit</div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 pt-3 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowDepositModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-xl font-bold text-start">Deposit</h2>
            <h2 className="text-md font-bold text-start mb-4">
              Enter Deposit Amount
            </h2>
            <input
              placeholder="Enter amount"
              type="number"
              className="w-full rounded rounded-lg"
              value={depositAmount}
              onChange={(e) => setDepositAmount(parseInt(e.target.value))}
            />
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={handleDeposit}
            >
              Deposit
            </button>
          </div>
        </div>
      )}
      {showWithdrawModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50">Withdraw</div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-6 pt-3 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowWithdrawModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-xl font-bold text-start">Withdraw</h2>

            <div>
              <h2 className="text-md font-bold text-start mb-2">
                Withdrawal Address
              </h2>
              <input
                placeholder="Enter address"
                type="text"
                className="w-full rounded rounded-lg"
                value={withdrawAddress}
                onChange={(e) => setWithdrawAddress(e.target.value)}
              />
            </div>
            <div>
              <h2 className="text-md font-bold text-start mb-2">
                Enter Withdrawal Amount
              </h2>
              <div className="flex items-center space-x-3">
                <input
                  placeholder="Enter amount"
                  type="number"
                  className="w-full rounded rounded-lg"
                  value={withdrawAmount}
                  onChange={(e) => setWithdrawAmount(parseInt(e.target.value))}
                />
                <button
                  onClick={handleSelectAllAmount}
                  className="bg-green-400 text-black w-[150px] px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
                >
                  Select All
                </button>
              </div>
            </div>
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={handleWithdraw}
            >
              Withdraw
            </button>
          </div>
        </div>
      )}
      <h1 className="text-start text-lg mt-8 mb-8">Delegation Summary</h1>
      <table>
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold text-sm">
              DELEGATION ADDRESS
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold text-sm">
              POOL ADDRESS{" "}
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold text-sm">
              DELEGATION BALANCE
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold text-sm"></th>
          </tr>
        </thead>
        <tbody>
          {delegations.map((delegationInfo) => {
            return (
              <tr
                key={delegationInfo.pool_address}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  <div className="flex justify-between space-x-2">
                    <p>
                      {delegationInfo.delegation_address.slice(0, 9)}...
                      {delegationInfo.delegation_address.slice(-4)}
                    </p>
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(
                          delegationInfo.delegation_address
                        )
                      }
                      className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                    >
                      <AiOutlineCopy />
                    </button>
                  </div>
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {delegationInfo.pool_address.slice(0, 8)}...
                  {delegationInfo.pool_address.slice(-4)}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {delegationInfo.delegation_balance}
                </td>

                <td className="py-2 px-4 border-b border-gray-200 flex justify-between space-x-2">
                  <button
                    onClick={() => {
                      setShowDepositModal(true);
                      setCurrentDelegationId(delegationInfo.delegation_address);
                    }}
                    className="px-2 py-1 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
                  >
                    DEPOSIT
                  </button>
                  <button
                    onClick={() => {
                      setShowWithdrawModal(true);
                      setCurrentDelegationId(delegationInfo.delegation_address);
                    }}
                    className="px-2 py-1 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
                  >
                    WITHRAW
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <hr className="my-12 h-[2px] bg-gradient-to-r from-transparent via-neutral-500 to-transparent opacity-25 dark:via-neutral-800" />{" "}
      <h2 className="mt-8 mb-8 text-lg text-start">Create New Delegation</h2>
      <p className="text-start">
        Maturity period: 2000 blocks (a block takes on averate 120 seconds)
      </p>
      <div className="container pt-8 text-start">
        <p className="pb-2">Pool address for new delegation</p>
        <input
          type="text"
          placeholder="Enter address"
          className="rounded rounded-lg"
          value={poolAddress}
          onChange={(e) => setPoolAddress(e.target.value)}
        />
      </div>
      <div className="container pt-8 text-start">
        <p className="pb-2">Delegation address</p>
        <input
          type="text"
          placeholder="Enter address"
          className="rounded rounded-lg"
          value={delegationAddress}
          onChange={(e) => setDelegationAddress(e.target.value)}
        />
      </div>
      <div>
        <button
          onClick={handleCreateDelegation}
          className="w-60 py-1 px-2 bg-[#69EE96] text-[#000000] rounded rounded-lg hover:text-[#69EE96] hover:bg-black mt-8 mb-8"
        >
          Create Delegation
        </button>
      </div>
    </div>
  );
};

export default Delegation;
