const { processAutoBids } = require("./routes/index"); // Adjust the path as needed

(async () => {
  try {
    await processAutoBids();
    console.log("Auto bids processed successfully!");
    process.exit(0);
  } catch (error) {
    console.error("Error processing auto bids:", error);
    process.exit(1);
  }
})();
