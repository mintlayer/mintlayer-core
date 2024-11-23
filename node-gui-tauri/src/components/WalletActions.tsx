import { useState } from "react";
import Addresses from "./Addresses";
import Console from "./Console";
import Delegation from "./Delegation";
import Send from "./Send";
import Staking from "./Staking";
import Transactions from "./Transactions";
import { IoCloseSharp } from "react-icons/io5";
import { invoke } from "@tauri-apps/api/core";
import { notify } from "../utils/util";
import { AccountType, ChainInfoType, WalletInfo } from "../types/Types";
const WalletActions = (props: {
  currentWallet: WalletInfo | undefined;
  currentAccount: AccountType | undefined;
  activeTab: string;
  currentAccountId: number;
  chainInfo: ChainInfoType | undefined;
  handleUpdateCurrentAccount: (index: string, address: string) => void;
  handleUpdateCurrentWalletEncryptionState: (
    wallet_id: string,
    encrypted: string
  ) => void;
  handleRemoveWallet: (wallet_id: string) => void;
}) => {
  const [showEncryptWalletModal, setShowEncryptWalletModal] = useState(false);
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [walletState, setWalletState] = useState(
    props.currentWallet?.encryption
  );
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
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          action: "set_password",
          password: password,
        },
      });
      if (result) {
        setWalletState("EnabledUnLocked");
        props.handleUpdateCurrentWalletEncryptionState(
          props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "",
          "EnabledUnlocked"
        );
        setShowEncryptWalletModal(false);
        notify("Wallet encrypted successfully.", "success");
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
            wallet_id: parseInt(
              props.currentWallet?.wallet_id
                ? props.currentWallet.wallet_id
                : "0"
            ),
            action: "remove_password",
          },
        });
        if (result) {
          setWalletState("Disabled");
          props.handleUpdateCurrentWalletEncryptionState(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "",
            "Disabled"
          );
          notify("Wallet encryption disabled successfully.", "success");
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
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          action: "lock",
        },
      });
      if (result) {
        setWalletState("EnabledLocked");
        props.handleUpdateCurrentWalletEncryptionState(
          props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "",
          "EnabledLocked"
        );
        notify("Wallet locked successfully.", "success");
      }
    } catch (err) {
      notify(new String(err).toString(), "error");
    }
  };

  const handleUnlock = async () => {
    try {
      const result = await invoke("update_encryption_wrapper", {
        request: {
          wallet_id: parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          ),
          action: "unlock",
          password: unLockPassword,
        },
      });
      if (result) {
        setWalletState("EnabledUnLocked");
        props.handleUpdateCurrentWalletEncryptionState(
          props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "",
          "EnabledUnlocked"
        );
        notify("Wallet unlocked successfully.", "success");
      }
    } catch (err) {
      notify(new String(err).toString(), "error");
    }
    setShowUnlockModal(false);
    setUnLockPassword("");
  };

  const handleCloseWallet = async (wallet_id: number) => {
    try {
      const result: string = await invoke("close_wallet_wrapper", {
        walletId: wallet_id,
      });
      props.handleRemoveWallet(result);
      notify("Wallet closed successfully.", "success");
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
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
            <div className="font-bold">
              {props.currentAccount?.balance.coins.decimal} TML
            </div>
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
              className={`py-1 px-2 ${
                !props.currentWallet
                  ? "bg-gray-400 cursor-not-allowed"
                  : "bg-[#69EE96] hover:text-[#69EE96] hover:bg-black"
              } rounded-lg bg-[#69EE96] text-[#000000] rounded hover:text-[#69EE96] hover:bg-black`}
              onClick={handleUpdateWalletEncryption}
            >
              {walletState === "EnabledUnLocked"
                ? "Disable Wallet Encryption"
                : "Encrypt Wallet"}
            </button>
          )}
          <button
            className={`py-1 px-4 ${
              !props.currentWallet
                ? "bg-gray-400 cursor-not-allowed"
                : "bg-white hover:outline-none hover:bg-[#E02424] hover:text-white hover:border-[#E02424]"
            } mt-8 mb-8 border text-[#E02424] border-[#E02424]  rounded-lg transition-all duration-200 `}
            onClick={() =>
              handleCloseWallet(
                parseInt(
                  props.currentWallet?.wallet_id
                    ? props.currentWallet.wallet_id
                    : "0"
                )
              )
            }
          >
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
          currentAccount={props.currentAccount}
          walletId={parseInt(
            props.currentWallet?.wallet_id ? props.currentWallet.wallet_id : "0"
          )}
          accountId={props.currentAccountId}
        />
      )}
      {props.activeTab === "staking" && (
        <Staking
          chainInfo={props.chainInfo}
          currentAccount={props.currentAccount}
          currentWallet={props.currentWallet}
          currentAccountId={props.currentAccountId}
          currentWalletId={props.currentWallet?.wallet_id}
        />
      )}
      {props.activeTab === "delegation" && (
        <Delegation
          currentAccount={props.currentAccount}
          currentAccountId={props.currentAccountId}
          currentWallet={props.currentWallet}
        />
      )}
      {props.activeTab === "console" && (
        <Console
          currentAccount={props.currentAccount}
          currentWallet={props.currentWallet}
          currentAccountId={props.currentAccountId}
        />
      )}
    </div>
  );
};
export default WalletActions;
