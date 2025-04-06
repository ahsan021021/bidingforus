const mongoose = require("mongoose")

const ProjectsSchema = mongoose.Schema({
    projectTitle:String,
    bidDescription:String,
    bidAmount:Number,
    status:Number,
    userName:String,
    time:{ type: Date},
    user : {type : mongoose.Types.ObjectId, ref:"Users"}
},{ timestamps: true })


module.exports = mongoose.model("Projects", ProjectsSchema)