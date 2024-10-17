import { useState } from "react";
import { AiOutlineCopy } from "react-icons/ai";

const Staking = () => {
  const stakingPoolInfo = [
    {
      pool_address: "tpool2134rfwer23r23r2ewr23r23r",
      margin_ratio: "50%",
      cost_per_block: 10,
      pool_balance: 50000,
    },
    {
      pool_address: "tpool2134rfwer23r23r2ewr23r23r",
      margin_ratio: "50%",
      cost_per_block: 10,
      pool_balance: 50000,
    },
    {
      pool_address: "tpool2134rfwer23r23r2ewr23r23r",
      margin_ratio: "50%",
      cost_per_block: 10,
      pool_balance: 50000,
    },
    {
      pool_address: "tpool2134rfwer23r23r2ewr23r23r",
      margin_ratio: "50%",
      cost_per_block: 10,
      pool_balance: 50000,
    },
  ];
  const [pledgeAmount, setPledgeAmount] = useState(0);
  const [costPerBlock, setCostPerBlock] = useState(0);
  const [marginRatio, setMarginRatio] = useState(0);
  const [decommissionAddress, setDecommissionAddress] = useState("");
  const [poolAddress, setPoolAddress] = useState("");
  const [receiveAddress, setReceiveAddress] = useState("");
  return (
    <div className="container overflow-y-auto px-4 pt-1 py-2">
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
          className="rounded rounded-lg"
          value={marginRatio}
          onChange={(e) => setMarginRatio(parseInt(e.target.value))}
        />
      </div>
      <div className="container pt-4 pb-2">
        <p className="text-start">Decommission</p>
        <input
          type="number"
          placeholder="Enter address"
          className="rounded rounded-lg"
          value={decommissionAddress}
          onChange={(e) => setDecommissionAddress(e.target.value)}
        />
      </div>
      <div>
        <button className="w-60 py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black mt-8 mb-8">
          Create Staking Pool
        </button>
      </div>
      <table>
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
          {stakingPoolInfo.map((stakeInfo, index) => {
            return (
              <tr
                key={stakeInfo.pool_address}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  {index + 1}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  <div className="flex justify-between space-x-2">
                    <p>
                      {stakeInfo.pool_address.slice(0, 9)}...
                      {stakeInfo.pool_address.slice(-4)}
                    </p>
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(stakeInfo.pool_address)
                      }
                      className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                    >
                      <AiOutlineCopy />
                    </button>
                  </div>
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.margin_ratio}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.cost_per_block}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {stakeInfo.pool_balance}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  <button className="w-full px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
                    DECOMMISSION
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="container">
        <p>Pool address to decommission</p>
        <input
          type="text"
          placeholder="Enter address"
          className="rounded rounded-lg"
          value={poolAddress}
          onChange={(e) => setPoolAddress(e.target.value)}
        />
      </div>
      <div className="container">
        <p>Address that will receive the proceeds from the staking pool</p>
        <input
          type="text"
          placeholder="Enter address"
          className="rounded rounded-lg"
          value={receiveAddress}
          onChange={(e) => setReceiveAddress(e.target.value)}
        />
      </div>
      <div>
        <button className="py-1 px-4 mt-8 mb-8 border border-[#E02424] text-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]">
          Decommission Staking Pool
        </button>
      </div>
    </div>
  );
};

export default Staking;
