import Addresses from "./Addresses";
import Console from "./Console";
import Delegation from "./Delegation";
import Send from "./Send";
import Staking from "./Staking";
import Transactions from "./Transactions";
const WalletActions = (props: any) => {
  return (
    <div className="container space-y-2 overflow-y-auto pt-4">
      <div className="row flex items-center justify-between pl-8 pr-8 pb-0">
        <div>
          <span className="flex inline-block space-x-2">
            <div className="font-thin">My balance: </div>
            <div className="font-bold">{} ML</div>
          </span>
        </div>
        <div className="space-x-2">
          <button className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
            Encrypt Wallet
          </button>
          <button className="py-1 px-4 mt-8 mb-8 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]">
            Close Wallet
          </button>
        </div>
      </div>
      {props.activeTab === "transactions" && <Transactions />}
      {props.activeTab === "addresses" && <Addresses />}
      {props.activeTab === "send" && <Send />}
      {props.activeTab === "staking" && <Staking />}
      {props.activeTab === "delegation" && <Delegation />}
      {props.activeTab === "console" && <Console />}
    </div>
  );
};
export default WalletActions;
