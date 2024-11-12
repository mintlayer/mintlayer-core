import { useEffect, useState } from "react";
import Addresses from "./Addresses";
import Console from "./Console";
import Delegation from "./Delegation";
import Send from "./Send";
import Staking from "./Staking";
import Transactions from "./Transactions";
import { IoCloseSharp } from "react-icons/io5";
import { invoke } from "@tauri-apps/api/core";
import { notify } from "../utils/util";
import { AccountType, WalletInfo } from "../types/Types";
const WalletActions = (props: {
  currentWallet: WalletInfo | undefined;
  currentAccount: AccountType | undefined;
  showNewAccountModal: boolean;
  activeTab: string;
  currentAccountId: number;
  handleUpdateCurrentAccount: (index: string, address: string) => void;
  handleUpdateCurrentWalletEncryptionState: (
    wallet_id: number,
    encrypted: string
  ) => void;
}) => {
  const [showEncryptWalletModal, setShowEncryptWalletModal] = useState(false);
  const [showNewAccountModal, setShowNewAccountModal] = useState(
    props.showNewAccountModal
  );
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [walletState, setWalletState] = useState(
    props.currentWallet?.encryption
  );
  const [accountName, setAccountName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [unLockPassword, setUnLockPassword] = useState("");
  const [error, setError] = useState("");

  const handleConfirmPasswordChange = (confirmPassword: string) => {
    setConfirmPassword(confirmPassword);

    // Validate the confirm password
    if (confirmPassword !== password) {
      setError("Passwords do not match.");
    } else if (confirmPassword.length < 8 || confirmPassword.length > 64) {
      setError("Password must be between 8 and 64 characters.");
    } else {
      setError("");
    }
  };

  const handleEncryptWallet = async () => {
    try {
      const result = await invoke("update_encryption_wrapper", {
        request: {
          wallet_id: props.currentWallet?.wallet_id,
          action: "set_password",
          password: password,
        },
      });
      if (result) {
        setWalletState("EnabledUnLocked");
        setShowEncryptWalletModal(false);
        notify("Wallet encrypted successfully.", "info");
      }
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
    setShowEncryptWalletModal(false);
    setPassword("");
    setConfirmPassword("");
  };

  const handleUpdateWalletEncryption = async () => {
    if (walletState === "EnabledUnLocked") {
      try {
        const result = await invoke("update_encryption_wrapper", {
          request: {
            wallet_id: props.currentWallet?.wallet_id,
            action: "remove_password",
          },
        });
        if (result) {
          setWalletState("Disabled");
          notify("Wallet encryption disabled successfully.", "info");
        }
      } catch (error) {
        notify(new String(error).toString(), "error");
      }
    } else {
      setShowEncryptWalletModal(true);
    }
  };

  const handleLockWallet = async () => {
    try {
      const result = await invoke("update_encryption_wrapper", {
        request: {
          wallet_id: props.currentWallet?.wallet_id,
          action: "lock",
        },
      });
      if (result) {
        setWalletState("EnabledLocked");
        notify("Wallet locked successfully.", "info");
      }
    } catch (err) {
      notify(new String(err).toString(), "error");
    }
  };

  const handleCreateWallet = () => {
    setShowNewAccountModal(false);
  };

  const handleUnlock = async () => {
    try {
      const result = await invoke("update_encryption_wrapper", {
        request: {
          wallet_id: props.currentWallet?.wallet_id,
          action: "unlock",
          password: unLockPassword,
        },
      });
      if (result) {
        setWalletState("EnabledUnLocked");
        notify("Wallet unlocked successfully.", "info");
      }
    } catch (err) {
      notify(new String(err).toString(), "error");
    }
    setShowUnlockModal(false);
    setUnLockPassword("");
  };

  return (
    <div className="bg-white border border-gray-200 shadowoverflow-y-auto mt-8 p-8 m-8 rounded rounded-lg shadow">
      {showEncryptWalletModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowEncryptWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Encrypt Wallet</h2>
            <input
              placeholder="Enter password"
              type="password"
              className="w-full rounded rounded-lg"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <input
              placeholder="Repeat password"
              type="password"
              className="w-full rounded rounded-lg"
              value={confirmPassword}
              onChange={(e) => handleConfirmPasswordChange(e.target.value)}
            />
            {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => handleEncryptWallet()}
            >
              Encrypt Wallet
            </button>
          </div>
        </div>
      )}
      {showNewAccountModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowEncryptWalletModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">New Account</h2>
            <input
              placeholder="Enter a name"
              type="text"
              className="w-full rounded rounded-lg"
              value={accountName}
              onChange={(e) => setAccountName(e.target.value)}
            />

            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={() => handleCreateWallet()}
            >
              Create
            </button>
          </div>
        </div>
      )}
      {showUnlockModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50">
          <div className="absolute inset-0 bg-black opacity-50"></div>
          <div className="bg-white rounded-lg shadow-lg z-10 p-4 max-w-lg mx-auto relative space-y-4">
            {/* Close Button */}
            <button
              className="absolute top-2 right-2 bg-transparent border-none shadow-none focus:outline-none "
              onClick={() => setShowUnlockModal(false)}
            >
              <IoCloseSharp />
            </button>
            <h2 className="text-lg font-bold mb-4">Unlock</h2>
            <input
              placeholder="Enter a name"
              type="password"
              className="w-full rounded rounded-lg"
              value={unLockPassword}
              onChange={(e) => setUnLockPassword(e.target.value)}
            />

            <button
              className="bg-green-400 text-black w-full px-2 py-1 rounded-lg hover:bg-[#000000] hover:text-green-400 transition duration-200"
              onClick={handleUnlock}
            >
              Unlock
            </button>
          </div>
        </div>
      )}
      <div className="row flex items-center justify-between pl-8 pr-8 pb-0">
        <div>
          <span className="flex inline-block space-x-2">
            <div className="font-thin">My balance: </div>
            <div className="font-bold">{} ML</div>
          </span>
        </div>
        <div className="space-x-2">
          {walletState === "EnabledLocked" && (
            <button
              className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
              onClick={() => {
                setShowUnlockModal(true);
              }}
            >
              UnLock
            </button>
          )}
          {walletState === "EnabledUnLocked" && (
            <button
              className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black "
              onClick={handleLockWallet}
            >
              Lock
            </button>
          )}
          {walletState !== "EnabledLocked" && (
            <button
              className="py-1 px-2 rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black"
              onClick={handleUpdateWalletEncryption}
            >
              {walletState === "EnabledUnLocked"
                ? "Disable Wallet Encryption"
                : "Encrypt Wallet"}
            </button>
          )}
          <button className="py-1 px-4 mt-8 mb-8 border text-[#E02424] border-[#E02424] bg-white rounded-lg transition-all duration-200 hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]">
            Close Wallet
          </button>
        </div>
      </div>
      {props.activeTab === "transactions" && (
        <Transactions transactions={props.currentAccount?.transaction_list} />
      )}
      {props.activeTab === "addresses" && (
        <Addresses
          addresses={
            props.currentAccount?.addresses
              ? props.currentAccount.addresses
              : {}
          }
          walletId={parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          )}
          accountId={props.currentAccountId}
          handleUpdateCurrentAccount={props.handleUpdateCurrentAccount}
        />
      )}
      {props.activeTab === "send" && (
        <Send
          walletId={parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          )}
          accountId={props.currentAccountId}
        />
      )}
      {props.activeTab === "staking" && <Staking />}
      {props.activeTab === "delegation" && <Delegation />}
      {props.activeTab === "console" && <Console />}
    </div>
  );
};
export default WalletActions;
