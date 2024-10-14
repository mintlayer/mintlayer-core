const SummaryTab = (props: any) => {
  return (
    <div className="containner">
      <p className="py-10">
        The following is a syncing state of your node. In a healthy network, the
        block timestamp should be close to the current wall-clock time.
      </p>
      <table className="min-w-full border border-gray-200">
        <tbody>
          <tr key="network" className="border-b">
            <td className="py-2 px-4 font-semibold text-gray-700 border-r border-gray-300 w-1/2">
              Network
            </td>
            <td className="py-2 px-4 font-semibold text-gray-600">
              {props.network}
            </td>
          </tr>
          <tr key="network" className="border-b">
            <td className="py-2 px-4 font-semibold text-gray-700 border-r border-gray-300 w-1/2">
              Best Block ID
            </td>
            <td className="py-2 px-4 font-semibold text-gray-600">
              {props.network}
            </td>
          </tr>
          <tr key="network" className="border-b">
            <td className="py-2 px-4 font-semibold text-gray-700 border-r border-gray-300 w-1/2">
              Best Block Height
            </td>
            <td className="py-2 px-4 font-semibold text-gray-600">
              {props.network}
            </td>
          </tr>
          <tr key="network" className="border-b">
            <td className="py-2 px-4 font-semibold text-gray-700 border-r border-gray-300 w-1/2">
              Best Block Timestamp (UTC)
            </td>
            <td className="py-2 px-4 font-semibold text-gray-600">
              {props.network}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export default SummaryTab;
