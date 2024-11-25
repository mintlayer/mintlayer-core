import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { AiOutlineCopy } from "react-icons/ai";
import { IoCloseSharp } from "react-icons/io5";
import {
  encode,
  encodeToBytesForAddress,
  encodeToHash,
  notify,
} from "../utils/util";
import {
  AccountType,
  WalletInfo,
  ToggleStakingResultType,
  Data,
  ChainInfoType,
} from "../types/Types";

const Staking = (props: {
  chainInfo: ChainInfoType | undefined;
  currentAccount: AccountType | undefined;
  currentWallet: WalletInfo | undefined;
  currentAccountId: number | undefined;
  currentWalletId: string | undefined;
}) => {
  // const [poolInfo, setPoolInfo] = useState(
  //   props.currentAccount?.staking_balance
  // );
  const [currentPoolId, setCurrentPoolId] = useState("");
  const [pledgeAmount, setPledgeAmount] = useState(0);
  const [costPerBlock, setCostPerBlock] = useState(0);
  const [marginRatio, setMarginRatio] = useState(0);
  const [decommissionAddress, setDecommissionAddress] = useState("");
  const [isStakingStarted, setIsStakingStarted] = useState(false);
  const [showDecommissionModal, setShowDecommissionModal] = useState(false);
  const [poolAddress, setPoolAddress] = useState("");
  const [receiveAddress, setReceiveAddress] = useState("");
  const [transactionInfo, setTransactionInfo] = useState<Data>();
  const [isLoading, setIsLoading] = useState(false);
  const [loadingMessage, setLoadingMessage] = useState("");
  const [showConfirmTransactionModal, setShowConfirmTransactionModal] =
    useState(false);
  const [showSuccessModal, setShowSuccessModal] = useState(false);
  const handleStaking = async () => {
    try {
      setLoadingMessage(
        isStakingStarted
          ? "Stopping Staking. Please wait."
          : "Starting Staking, Please wait."
      );
      setIsLoading(true);
      const result: ToggleStakingResultType = await invoke(
        "toggle_stakig_wrapper",
        {
          request: {
            wallet_id: parseInt(
              props.currentWalletId ? props.currentWalletId : "0"
            ),
            account_id: props.currentAccountId ? props.currentAccountId : 0,
            enabled: !isStakingStarted,
          },
        }
      );
      if (result) {
        setIsStakingStarted(result.enabled);
        notify(
          result.enabled ? "Staking started" : "Staking stopped",
          "success"
        );
        setIsLoading(false);
      }
    } catch (error) {
      const errorMessage = new String(error);
      notify(errorMessage.toString(), "error");
    }
    setIsLoading(false);
  };
  const handleDecommission = async () => {
    try {
      setLoadingMessage("Decommissioning Staking Pool. Please wait.");
      setIsLoading(true);
      const result = await invoke("decommission_pool_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWalletId ? props.currentWalletId : "0"
          ),
          account_id: props.currentAccountId ? props.currentAccountId : 0, // Change to parseInt
          pool_id: currentPoolId,
          output_address: receiveAddress,
        },
      });
      if (result) {
        notify("Pool decommissioned", "success");
      }
    } catch (error) {
      const regex = /Wallet error: (.+)/;
      const errorMessage = new String(error).match(regex);
      if (errorMessage) {
        notify(errorMessage[1], "error");
      }
    }
    setShowDecommissionModal(false);
    setIsLoading(false);
  };

  const handleCreateStakingPool = async () => {
    try {
      setLoadingMessage("Creating Staking Pool. Please wait");
      setIsLoading(true);
      const result: Data = await invoke("stake_amount_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWalletId ? props.currentWalletId : "0"
          ),
          account_id: props.currentAccountId ? props.currentAccountId : 0, // Change to parseInt
          pledge_amount: pledgeAmount.toString(),
          mpt: marginRatio.toString(),
          cost_per_block: costPerBlock.toString(),
          decommission_address: decommissionAddress,
        },
      });
      if (result) {
        console.log("trasaction info is =========>", result);
        setTransactionInfo(result);
        setShowConfirmTransactionModal(true);
      }
    } catch (error) {
      const regex = /Wallet error: (.+)/;
      const errorMessage = new String(error).match(regex);
      if (errorMessage) {
        notify(errorMessage[1], "error");
      }
    }
    setIsLoading(false);
  };
  const handleConfirmTransaction = async () => {
    try {
      const result = await invoke("submit_transaction_wrapper", {
        request: {
          wallet_id: props.currentWalletId,
          account_id: props.currentAccountId,
          tx: transactionInfo?.tx,
        },
      });
      console.log("sending amount transaction result is ========>", result);
      notify("Transaction confirmed successfully!", "success");
      setShowSuccessModal(true);
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };

  return (
    <div className="container overflow-y-auto px-4 pt-1 py-2">
      <style>{`
        /* Hide the spin buttons for WebKit-based browsers */
        input[type="number"]::-webkit-inner-spin-button,
        input[type="number"]::-webkit-outer-spin-button {
          -webkit-appearance: none;
          margin: 0;
        }

        /* Hide the spin buttons for Firefox */
        input[type="number"] {
          -moz-appearance: textfield;
        }
      `}</style>
      {isLoading && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-opacity-50 z-10 p-6 max-w-lg mx-auto relative space-y-4">
            <div className="loader px-10">{loadingMessage}</div>
          </div>
        </div>
      )}
      {showDecommissionModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowDecommissionModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">
              Decommission Staking Pool
            </h2>
            <p className="text-start">Pool address to decommission</p>

            <input
              placeholder="Enter address"
              type="text"
              className="w-full rounded rounded-lg"
              value={poolAddress}
              onChange={(e) => setPoolAddress(e.target.value)}
            />
            <p className="text-start">
              Address that will receive the proceeds from the staking pool
            </p>

            <input
              placeholder="Enter address"
              type="text"
              className="w-full rounded rounded-lg"
              value={receiveAddress}
              onChange={(e) => setReceiveAddress(e.target.value)}
            />
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={handleDecommission}
            >
              Decommission
            </button>
          </div>
        </div>
      )}

      {showConfirmTransactionModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div
            className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4"
            style={{ minWidth: "300px", maxWidth: "90%" }}
          >
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowConfirmTransactionModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Confirm Transaction</h2>
            <p className="text-start text-bold">Transaction summary</p>
            <div>
              <p className="text-start text-bold">TRANSACTION ID</p>
              <p className="text-start">
                {encodeToHash(
                  JSON.stringify(
                    transactionInfo?.tx.transaction.V1
                      ? transactionInfo.tx.transaction.V1
                      : {}
                  )
                )}
              </p>
            </div>
            <div>
              <p className="text-start text-bold">BEGIN OF INPUTS</p>
              <p className="text-start">
                -Transaction({"0x"}
                {
                  transactionInfo?.tx.transaction.V1.inputs[0].Utxo.id
                    .Transaction
                }
                )
              </p>
            </div>
            <div>
              <p className="text-start  text-bold">END OF INPUTS</p>
            </div>
            <div>
              <p className="text-start">BEGIN OF OUTPUTS</p>
              {transactionInfo?.tx.transaction.V1.outputs.find(
                (output) => "CreateStakePool" in output
              ) ? (
                <>
                  <p className="text-start">
                    -CreateStakePool(Id(
                    {encode(
                      "tpool",
                      encodeToBytesForAddress(
                        new String(
                          transactionInfo?.tx.transaction.V1.outputs.find(
                            (output) => "CreateStakePool" in output
                          )?.CreateStakePool[0]
                        ).toString()
                      )
                    )}
                    )), Pledge(
                    {pledgeAmount})
                  </p>
                  <p className="text-start">
                    -Staker(
                    {encode(
                      "tpmt",
                      encodeToBytesForAddress(
                        new String(
                          transactionInfo?.tx.transaction.V1.outputs.find(
                            (output) => "CreateStakePool" in output
                          )?.CreateStakePool[1].staker
                        ).toString()
                      )
                    )}
                    )
                  </p>
                  <p className="text-start">
                    -Margin Ratio({marginRatio * 100}%)
                  </p>
                  <p className="text-start">-CostPerBlock({costPerBlock})</p>
                  <p className="text-start">
                    -Transfer(
                    {encode(
                      "tmt",
                      encodeToBytesForAddress(
                        new String(
                          transactionInfo?.tx.transaction.V1.outputs.find(
                            (output) => "Transfer" in output
                          )?.Transfer[1]
                        ).toString()
                      )
                    )}
                    ,{" "}
                    {parseInt(
                      new String(
                        transactionInfo?.tx.transaction.V1.outputs.find(
                          (output) => "Transfer" in output
                        )?.Transfer[0].Coin.atoms
                      ).toString()
                    ) / 1000000000000}
                    )
                  </p>
                </>
              ) : (
                <>
                  <p className="text-start">
                    -LockThenTransfer(
                    {encode(
                      "tpool",
                      encodeToBytesForAddress(
                        new String(
                          transactionInfo?.tx.transaction.V1.outputs.find(
                            (output) => "LockThenTransfer" in output
                          )?.LockThenTransfer[0]
                        ).toString()
                      )
                    )}
                    ),{" "}
                    {parseInt(
                      new String(
                        transactionInfo?.tx.transaction.V1.outputs.find(
                          (output) => "LockThenTransfer" in output
                        )?.LockThenTransfer[1].Coin.atoms
                      ).toString()
                    ) / 1000000000000}
                    {", "}
                    {new String(
                      transactionInfo?.tx.transaction.V1.outputs.find(
                        (output) => "LockThenTransfer" in output
                      )?.LockThenTransfer[2]
                    ).toString()}
                  </p>
                </>
              )}
            </div>
            <div>
              <p className="text-start text-bold">END OF OUTPUTS</p>
            </div>
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => {
                handleConfirmTransaction();
                setShowConfirmTransactionModal(false);
              }}
            >
              Confirm and Broadcast
            </button>
          </div>
        </div>
      )}

      {showSuccessModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowSuccessModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Success</h2>
            <p className="text-start">
              Please wait for your transaction to be included in a block
            </p>

            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => setShowSuccessModal(false)}
            >
              Okay
            </button>
          </div>
        </div>
      )}
      <div className="border border-gray-200 rounded rounded-lg w-full py-6">
        <p className="font-bold text-lg text-center">RUN STAKING POOLS</p>
        <p className="text-center py-6">
          {isStakingStarted
            ? "Staking is active"
            : "Staking has not yet started"}
        </p>
        <button
          className={
            isStakingStarted
              ? "py-1 px-4 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]"
              : "w-40 py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
          }
          onClick={handleStaking}
        >
          {isStakingStarted ? "STOP STAKING" : "BEGIN STAKING"}
        </button>
      </div>
      <p className="text-lg text-start py-8">Staking Pool Summary</p>
      <table className="rounded rounded-lg overflow-hidden shadow">
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold"></th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              POOL ADDRESS
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              MARGIN RATIO
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              COST PER BLOCK
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              POOL BALANCE
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold"></th>
          </tr>
        </thead>
        <tbody>
          {Object.values(
            props.currentAccount?.staking_balance
              ? props.currentAccount?.staking_balance
              : {}
          ).map((stakeInfo, index) => {
            return (
              <tr
                key={stakeInfo.pool_id}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  {index + 1}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  <div className="flex justify-between space-x-2">
                    <p>
                      {stakeInfo.pool_id.slice(0, 9)}...
                      {stakeInfo.pool_id.slice(-4)}
                    </p>
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(stakeInfo.pool_id)
                      }
                      className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                    >
                      <AiOutlineCopy />
                    </button>
                  </div>
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.margin_ratio_per_thousand}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.cost_per_block.decimal}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.balance.decimal}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  <button
                    onClick={() => {
                      setShowDecommissionModal(true);
                      setCurrentPoolId(stakeInfo.pool_id);
                    }}
                    className="py-1 px-4 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]"
                  >
                    DECOMMISSION
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="text-lg text-start py-8">Create Staking Pool</p>
      <p className="text-start">
        Maturity period: 2000 blocks (a block takes on averagte 120 seconds)
      </p>
      <div className="container pt-4">
        <p className="text-start">Pledge amount for the new staking pool</p>
        <input
          type="number"
          placeholder="Enter amount"
          className="rounded rounded-lg"
          value={pledgeAmount}
          onChange={(e) => setPledgeAmount(parseInt(e.target.value))}
        />
      </div>
      <div className="container pt-4">
        <p className="text-start">Cost per block</p>
        <input
          type="number"
          placeholder="Enter amount"
          className="rounded rounded-lg"
          value={costPerBlock}
          onChange={(e) => setCostPerBlock(parseInt(e.target.value))}
        />
      </div>
      <div className="container pt-4">
        <p className="text-start">
          Margin ratio per thousad. The decimal must be in the range [0.0001,
          1.000] or [0.1%, 100%]
        </p>
        <input
          type="number"
          placeholder="Enter amount"
          step="0.001"
          min={0}
          className="rounded rounded-lg"
          value={marginRatio}
          onChange={(e) => setMarginRatio(parseFloat(e.target.value))}
        />
      </div>
      <div className="container pt-4 pb-2">
        <p className="text-start">Decommission address</p>
        <input
          placeholder="Enter address"
          className="rounded rounded-lg border-black p-2"
          value={decommissionAddress}
          type="text"
          onChange={(e) => setDecommissionAddress(e.target.value)}
        />
      </div>
      <div>
        <button
          onClick={handleCreateStakingPool}
          className="w-60 py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black mt-8 mb-8"
        >
          Create Staking Pool
        </button>
      </div>
    </div>
  );
};

export default Staking;
