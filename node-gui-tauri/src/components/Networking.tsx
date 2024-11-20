import { PeerConnected } from "../types/Types";

const NetworkingTab = (props: {
  peerInfo: PeerConnected["P2p"]["PeerConnected"][];
}) => {
  // const networkInfo = [
  //   {
  //     socket: "139.177.176.199:3031",
  //     inbound: "Outbound",
  //     useragent: "Mintlayer Core",
  //     version: "0.6.1",
  //   },
  //   {
  //     socket: "172.16.31.10:8080",
  //     inbound: "Inbound",
  //     useragent: "BitTorrent",
  //     version: "1.0.1",
  //   },
  //   {
  //     socket: "192.168.127.12:3031",
  //     inbound: "Outbound",
  //     useragent: "Bitcoin Core",
  //     version: "0.21.1",
  //   },
  //   // Add more peers as needed...
  // ];
  return (
    <div className="pt-0 mt-8 m-8 rounded rounded-lg bg-white p-8">
      <p className="py-10">
        The following is a list of peers connected to your node
      </p>
      <table className="min-w-full border border-gray-200">
        <thead className="bg-gray-100 ">
          <tr>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold"></th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              #SOCKET
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              INBOUND
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              USER AGENT
            </th>
            <th className="py-3 px-4 text-center text-gray-600 font-semibold">
              VERSION
            </th>
          </tr>
        </thead>
        <tbody>
          {props.peerInfo.map((netInfo) => {
            return (
              <tr
                key={netInfo.address}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.id}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.address}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.inbound === true ? "Inbound" : "Outbound"}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.user_agent
                    ?.map((value) => String.fromCharCode(value))
                    .join("")}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.software_version.major}.
                  {netInfo.software_version.minor}.
                  {netInfo.software_version.patch}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default NetworkingTab;
