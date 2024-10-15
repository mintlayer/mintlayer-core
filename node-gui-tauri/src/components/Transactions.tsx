import { FaCopy } from "react-icons/fa";

const Transactions = () => {
  const transactions = [
    {
      transaction_id: "9f4werwef323f4sd",
      timestamp: "2024-10-07 00:00:00",
      type: "Received",
      amount: "23423423",
      state: "Confirmed",
    },
    {
      transaction_id: "9f4werwef223f4sd",
      timestamp: "2024-10-07 00:00:00",
      type: "Sent",
      amount: "23423423",
      state: "Confirmed",
    },
    {
      transaction_id: "9f4werwef343f4sd",
      timestamp: "2024-10-07 00:00:00",
      type: " received",
      amount: "23423423",
      state: "Confirmed",
    },
  ];
  return (
    <div className="container space-y-4">
      <div className="row flex justify-between">
        <div className="col-md-8">
          <span className="flex inline-block space-x-2">
            <div className="font-thin">My balance: </div>
            <div className="font-bold">{} ML</div>
          </span>
        </div>
        <div className="col-md-4 space-x-2">
          <button className="py-1 px-2 rounded-2 bg-[#50d71e] text-[#000000] rounded hover:text-[#50d71e] hover:bg-black ">
            Encrypt Wallet
          </button>
          <button className="py-1 px-2 border-[1px] border-red-500 text-[#fa0000] rounded-2">
            Close Wallet
          </button>
        </div>
      </div>
      <table className="min-w-full border border-gray-200">
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              #
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              TRANSACTION ID
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              TIMESTAMP (UTC)
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              TYPE
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              AMOUNT
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              STATE
            </th>
          </tr>
        </thead>
        <tbody>
          {transactions.map((tranasctionInfo, index) => {
            return (
              <tr
                key={tranasctionInfo.timestamp.toString()}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  {index + 1}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  <div className="flex justify-between">
                    <p>
                      {tranasctionInfo.transaction_id.slice(0, 4)}...
                      {tranasctionInfo.transaction_id.slice(-4)}
                    </p>
                    <button
                      onClick={() =>
                        navigator.clipboard.writeText(
                          tranasctionInfo.transaction_id
                        )
                      }
                    >
                      <FaCopy />
                    </button>
                  </div>
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {tranasctionInfo.timestamp}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {tranasctionInfo.type}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {tranasctionInfo.amount}
                </td>
                <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                  {tranasctionInfo.state}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};
export default Transactions;
