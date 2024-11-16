import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";
import { AiOutlineCopy } from "react-icons/ai";
import { IoCloseSharp } from "react-icons/io5";
import { notify } from "../utils/util";
import {
  AccountType,
  WalletInfo,
  ToggleStakingResultType,
} from "../types/Types";

const Staking = (props: {
  currentAccount: AccountType | undefined;
  currentWallet: WalletInfo | undefined;
  currentAccountId: number | undefined;
  currentWalletId: string | undefined;
}) => {
  const [poolInfo, setPoolInfo] = useState(
    props.currentAccount?.staking_balance
  );
  const [pledgeAmount, setPledgeAmount] = useState(0);
  const [costPerBlock, setCostPerBlock] = useState(0);
  const [marginRatio, setMarginRatio] = useState(0);
  const [decommissionAddress, setDecommissionAddress] = useState("");
  const [isStakingStarted, setIsStakingStarted] = useState(false);
  const [showDecommissionModal, setShowDecommissionModal] = useState(false);
  const [poolAddress, setPoolAddress] = useState("");
  const [receiveAddress, setReceiveAddress] = useState("");
  const handleStaking = async () => {
    try {
      const result: ToggleStakingResultType = await invoke(
        "toggle_stakig_wrapper",
        {
          requst: {
            wallet_id: parseInt(
              props.currentWalletId ? props.currentWalletId : "0"
            ),
            account_id: props.currentAccountId ? props.currentAccountId : 0,
            enabled: !isStakingStarted,
          },
        }
      );
      if (result) {
        console.log(result);
        setIsStakingStarted(result.enabled);
        notify(
          result.enabled ? "Staking started" : "Staking stopped",
          "notify"
        );
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
    setIsStakingStarted((started) => !started);
  };
  const handleDecommission = () => {
    setShowDecommissionModal(false);
  };

  const handleCreateStakingPool = async () => {
    try {
      const result = await invoke("stake_amount_wrapper", {
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
        console.log(result);
      }
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
            <h2 className="text-lg font-bold mb-4">Encrypt Wallet</h2>
            <p className="text-start">Pool address to decommission</p>

            <input
              placeholder="Enter password"
              type="text"
              className="w-full rounded rounded-lg"
              value={poolAddress}
              onChange={(e) => setPoolAddress(e.target.value)}
            />
            <p className="text-start">
              Address that will receive the proceeds from the staking pool
            </p>

            <input
              placeholder="Repeat password"
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
          {Object.values(poolInfo ? poolInfo : {}).map((stakeInfo, index) => {
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
                  <button className="py-1 px-4 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]">
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
        <p className="text-start">Decommission</p>
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
