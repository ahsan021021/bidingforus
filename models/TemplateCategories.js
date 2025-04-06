const mongoose = require("mongoose");

const TemplateCategoriesSchema = mongoose.Schema(
  {
    name: String,
    always_include: Boolean,
    user: { type: mongoose.Types.ObjectId, ref: "Users" },
    position: Number
  },
  { timestamps: true }
);


module.exports = mongoose.model("TemplateCategories", TemplateCategoriesSchema)


