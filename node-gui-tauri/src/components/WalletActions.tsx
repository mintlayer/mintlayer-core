import Addresses from "./Addresses";
import Delegation from "./Delegation";
import Send from "./Send";
import Staking from "./Staking";
import Transactions from "./Transactions";
const WalletActions = (props: any) => {
  return (
    <div className="container space-y-2 overflow-y-auto">
      <div className="row flex justify-between pl-8 pr-8 pb-0">
        <div className="col-md-8">
          <span className="flex inline-block space-x-2">
            <div className="font-thin">My balance: </div>
            <div className="font-bold">{} ML</div>
          </span>
        </div>
        <div className="col-md-4 space-x-2">
          <button className="py-1 px-2 rounded-2 bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black ">
            Encrypt Wallet
          </button>
          <button className="py-1 px-2 border-[1px] border-red-500 text-[#fa0000] rounded-2">
            Close Wallet
          </button>
        </div>
      </div>
      {props.activeTab === "transactions" && <Transactions />}
      {props.activeTab === "addresses" && <Addresses />}
      {props.activeTab === "send" && <Send />}
      {props.activeTab === "staking" && <Staking />}
      {props.activeTab === "delegation" && <Delegation />}
    </div>
  );
};
export default WalletActions;
