const mongoose = require("mongoose");

const BiddingpriceSchema = mongoose.Schema({
    user: { type: mongoose.Types.ObjectId, ref: "Users" },

    // Predefined Budgets
    micro_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_aud_cad: { type: Number },
        bid_gbp: { type: Number },
        bid_eur: { type: Number },
        bid_inr: { type: Number },
        bid_nzd: { type: Number },
        bid_hkd: { type: Number },
        bid_sgd: { type: Number },
        budget_range_usd_aud_cad: { type: String, enum: ['10-30', '30-60'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['10-20'] },
        budget_range_eur: { type: String, enum: ['8-30'] },
        budget_range_inr: { type: String, enum: ['600-1500'] },
        budget_range_nzd: { type: String, enum: ['14-30'] },
        budget_range_hkd: { type: String, enum: ['80-240'] },
        budget_range_sgd: { type: String, enum: ['12-30'] }
    },
    simple_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_eur_aud_cad_nzd_sgd: { type: Number },
        bid_gbp: { type: Number },
        bid_inr: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_eur_aud_cad_nzd_sgd: { type: String, enum: ['30-250'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['20-250'] },
        budget_range_inr: { type: String, enum: ['1500-12500'] },
        budget_range_hkd: { type: String, enum: ['240-2000'] }
    },
    very_small_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_gbp_eur_aud_cad_nzd_sgd: { type: Number },
        bid_inr: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_gbp_eur_aud_cad_nzd_sgd: { type: String, enum: ['250-750'] }, // Example ranges
        budget_range_inr: { type: String, enum: ['12500-37500'] },
        budget_range_hkd: { type: String, enum: ['2000-6000'] }
    },
    small_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_gbp_eur_aud_cad_nzd_sgd: { type: Number },
        bid_inr: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_gbp_eur_aud_cad_nzd_sgd: { type: String, enum: ['750-1500'] }, // Example ranges
        budget_range_inr: { type: String, enum: ['37500-75000'] },
        budget_range_hkd: { type: String, enum: ['6000-12000'] }
    },
    medium_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_gbp_eur_aud_cad_nzd_sgd: { type: Number },
        bid_inr: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_gbp_eur_aud_cad_nzd_sgd: { type: String, enum: ['1500-3000'] }, // Example ranges
        budget_range_inr: { type: String, enum: ['75000-150000'] },
        budget_range_hkd: { type: String, enum: ['12000-24000'] }
    },
    large_project: {
        budget: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_gbp_eur_aud_cad_nzd_sgd: { type: Number },
        bid_inr: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_gbp_eur_aud_cad_nzd_sgd: { type: String, enum: ['3000-5000'] }, // Example ranges
        budget_range_inr: { type: String, enum: ['150000-250000'] },
        budget_range_hkd: { type: String, enum: ['24000-40000'] }
    },

    // Hourly Rates
    basic_hourly: {
        rate: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_aud_cad: { type: Number },
        bid_gbp: { type: Number },
        bid_eur: { type: Number },
        bid_inr: { type: Number },
        bid_nzd_sgd: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_aud_cad: { type: String, enum: ['2-8'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['2-5'] },
        budget_range_eur: { type: String, enum: ['2-6'] },
        budget_range_inr: { type: String, enum: ['100-400'] },
        budget_range_nzd_sgd: { type: String, enum: ['3-10'] },
        budget_range_hkd: { type: String, enum: ['16-65'] }
    },
    moderate_hourly: {
        rate: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_aud_cad: { type: Number },
        bid_gbp: { type: Number },
        bid_eur: { type: Number },
        bid_inr: { type: Number },
        bid_nzd_sgd: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_aud_cad: { type: String, enum: ['8-15'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['5-10'] },
        budget_range_eur: { type: String, enum: ['6-12'] },
        budget_range_inr: { type: String, enum: ['400-750'] },
        budget_range_nzd_sgd: { type: String, enum: ['10-20'] },
        budget_range_hkd: { type: String, enum: ['65-115'] }
    },
    standard_hourly: {
        rate: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_aud_cad: { type: Number },
        bid_gbp: { type: Number },
        bid_eur: { type: Number },
        bid_inr: { type: Number },
        bid_nzd_sgd: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_aud_cad: { type: String, enum: ['15-25'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['10-15'] },
        budget_range_eur: { type: String, enum: ['12-18'] },
        budget_range_inr: { type: String, enum: ['750-1250'] },
        budget_range_nzd_sgd: { type: String, enum: ['20-30'] },
        budget_range_hkd: { type: String, enum: ['115-200'] }
    },
    skilled_hourly: {
        rate: { type: String, enum: ['lowest', 'average', 'highest'] },
        bid_usd_aud_cad: { type: Number },
        bid_gbp: { type: Number },
        bid_eur: { type: Number },
        bid_inr: { type: Number },
        bid_nzd_sgd: { type: Number },
        bid_hkd: { type: Number },
        budget_range_usd_aud_cad: { type: String, enum: ['25-50'] }, // Example ranges
        budget_range_gbp: { type: String, enum: ['18-36'] },
        budget_range_eur: { type: String, enum: ['18-36'] },
        budget_range_inr: { type: String, enum: ['1250-2500'] },
        budget_range_nzd_sgd: { type: String, enum: ['30-60'] },
        budget_range_hkd: { type: String, enum: ['200-400'] }
    }
}, { timestamps: true });

module.exports = mongoose.model("Biddingprice", BiddingpriceSchema);