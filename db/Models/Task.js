//model for the task:
import mongoose from "mongoose";
const TaskShema = new mongoose.Schema({
title:{
    type:String,
    required:true,
    minlength:1,
    trim:true,
},
desc:{
    type:String,

},
type:{
    type:String,
}
,dueDate:{
    type:Date,
},
listid:{
    type:String,
    required:true,
},
completed:{
    type:Boolean,
    default:false,
}


}
    )
export default mongoose.model("Task",TaskShema)
