import { useState } from "react";
import { FaCopy } from "react-icons/fa";

const Delegation = () => {
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
  return (
    <div className="container pt-0 p-4 shadow-1">
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
                    >
                      <FaCopy />
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
                  <button className="px-2 rounded-2 bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
                    DEPOSIT
                  </button>
                  <button className="px-2 rounded-2 bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
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
          className="rounded rounded-2"
          value={poolAddress}
          onChange={(e) => setPoolAddress(e.target.value)}
        />
      </div>
      <div className="container pt-8 text-start">
        <p className="pb-2">Delegation address</p>
        <input
          type="text"
          placeholder="Enter address"
          className="rounded rounded-2"
          value={delegationAddress}
          onChange={(e) => setDelegationAddress(e.target.value)}
        />
      </div>
      <div>
        <button className="w-60 py-1 px-2 bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black mt-8 mb-8">
          Create Delegation
        </button>
      </div>
    </div>
  );
};

export default Delegation;
