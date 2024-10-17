import { AiOutlineCopy } from "react-icons/ai";

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
                    className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                  >
                    <AiOutlineCopy />
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
  );
};

export default Transactions;
