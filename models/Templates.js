const mongoose = require("mongoose")

const TemplateSchema = mongoose.Schema({
    
    content : String,
    skills : [String],
    category: { type: mongoose.Types.ObjectId, ref: "TemplateCategories" },
    SkillSets: { type: mongoose.Types.ObjectId, ref: "SkillSets" },
    userId : { type: mongoose.Types.ObjectId, ref: "Users" },
},{ timestamps: true })


module.exports = mongoose.model("Template", TemplateSchema)