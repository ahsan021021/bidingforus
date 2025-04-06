const mongoose = require("mongoose")

const PeriodsSchema = mongoose.Schema({
    higher : String,
    lower : String,
    period : String,
    user : {type : mongoose.Types.ObjectId, ref:"Users"}
},{ timestamps: true })


module.exports = mongoose.model("Periods", PeriodsSchema)