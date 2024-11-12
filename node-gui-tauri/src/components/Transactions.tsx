import { AiOutlineCopy } from "react-icons/ai";
import { Pagination } from "flowbite-react";
import { useState } from "react";
import { TransactionType } from "../types/Types";

const Transactions = (props: { transactions: TransactionType | undefined }) => {
  const [currentPage, setCurretPage] = useState(1);
  const onPageChange = (page: number) => {
    setCurretPage(page);
  };
  return (
    <div>
      <table className="min-w-full border border-gray-200 rounded rounded-lg overflow-hidden shadow">
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold ">
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
          {props.transactions?.txs
            ?.slice((currentPage - 1) * 10, currentPage * 10)
            .map((transactionInfo, index) => {
              return (
                <tr className="hover:bg-gray-50 transition duration-200">
                  <td className="py-2 px-4 border-b border-gray-200">
                    {index + 1}
                  </td>
                  <td className="py-2 px-4 border-b border-gray-200">
                    <div className="flex justify-between">
                      <p>
                        {transactionInfo.txid.slice(0, 4)}...
                        {transactionInfo.txid.slice(-4)}
                      </p>
                      <button
                        onClick={() =>
                          navigator.clipboard.writeText(transactionInfo.txid)
                        }
                        className="flex items-center justify-center p-0 bg-transparent border-none shadow-none focus:outline-none"
                      >
                        <AiOutlineCopy />
                      </button>
                    </div>
                  </td>
                  <td className="py-2 px-4 border-b border-gray-200">
                    {transactionInfo.timestamp.timestamp}
                  </td>
                  {(() => {
                    if ("Redeposit" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          Redeposit
                        </td>
                      );
                    }
                    if ("Received" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          Received
                        </td>
                      );
                    }
                    if ("Sent" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          Sent
                        </td>
                      );
                    }
                    if ("Other" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          Other
                        </td>
                      );
                    }
                  })()}

                  {(() => {
                    if ("Redeposit" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200"></td>
                      );
                    }

                    if ("Received" in transactionInfo.tx_type) {
                      const { amount } = transactionInfo.tx_type.Received;
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          {amount.atoms}
                        </td>
                      );
                    }

                    if ("Sent" in transactionInfo.tx_type) {
                      const { amount } = transactionInfo.tx_type.Sent;
                      return (
                        <td className="py-2 px-4 border-b border-gray-200">
                          {amount.atoms}
                        </td>
                      );
                    }

                    if ("Other" in transactionInfo.tx_type) {
                      return (
                        <td className="py-2 px-4 border-b border-gray-200"></td>
                      );
                    }
                  })()}
                  {(() => {
                    if ("Confirmed" in transactionInfo.state) {
                      return (
                        <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                          Confirmed
                        </td>
                      );
                    }

                    if ("InMempool" in transactionInfo.state) {
                      return (
                        <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                          InMempool
                        </td>
                      );
                    }

                    if ("Conflicted" in transactionInfo.state) {
                      return (
                        <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                          Conflicted
                        </td>
                      );
                    }

                    if ("Inactive" in transactionInfo.tx_type) {
                      return (
                        <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                          Inactive
                        </td>
                      );
                    }

                    if ("Abandoned" in transactionInfo.tx_type) {
                      return (
                        <td className="border-b mt-2 border-gray-200 flex items-center justify-center bg-green-200 text-black text-xs font-bold py-1 px-2 rounded-full h-full">
                          Abandoned
                        </td>
                      );
                    }
                  })()}
                </tr>
              );
            })}
        </tbody>
      </table>
      <div className="flex overflow-x-auto sm:justify-center">
        <Pagination
          layout="pagination"
          currentPage={currentPage}
          totalPages={
            props.transactions?.txs?.length ? props.transactions.txs.length : 0
          }
          onPageChange={onPageChange}
          previousLabel=""
          nextLabel=""
          showIcons
        />
      </div>
    </div>
  );
};

export default Transactions;
