import { toast } from "react-toastify";

export   const notify = (message: string, type: string) => {
    console.log("notification is displayed");
    switch (type) {
      case "error":
        toast.error(message);
        break;
      case "info":
        toast.info(message);
        break;
      case "success":
        toast.success(message);
        break;
      default:
        toast.info(message);
    }
  };