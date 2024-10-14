const NetworkingTab = () => {
  const networkInfo = [
    {
      socket: "139.177.176.199:3031",
      inbound: "Outbound",
      useragent: "Mintlayer Core",
      version: "0.6.1",
    },
    {
      socket: "172.16.31.10:8080",
      inbound: "Inbound",
      useragent: "BitTorrent",
      version: "1.0.1",
    },
    {
      socket: "192.168.127.12:3031",
      inbound: "Outbound",
      useragent: "Bitcoin Core",
      version: "0.21.1",
    },
    // Add more peers as needed...
  ];
  return (
    <div className="container">
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
          {networkInfo.map((netInfo, index) => {
            return (
              <tr
                key={netInfo.socket}
                className="hover:bg-gray-50 transition duration-200"
              >
                <td className="py-2 px-4 border-b border-gray-200">
                  {index + 1}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.socket}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.inbound}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.useragent}
                </td>
                <td className="py-2 px-4 border-b border-gray-200">
                  {netInfo.version}
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
