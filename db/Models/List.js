// this is the model for the list :
import mongoose from "mongoose";
const ListShema = new mongoose.Schema({
title:{
    type:String,
    required:true,
    minlength:1,
    trim:true,
},
_idUser:{
    type:mongoose.Schema.Types.ObjectId,
    required:true,
}


}
    )
export default mongoose.model("List",ListShema)
