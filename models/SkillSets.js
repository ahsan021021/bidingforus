const mongoose = require("mongoose")

const SkillSetsSchema = mongoose.Schema({
    name : String,
    skills : [String],
    user : {type : mongoose.Types.ObjectId, ref:"Users"}
},{ timestamps: true })


module.exports = mongoose.model("SkillSets", SkillSetsSchema)