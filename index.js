import mongoose from "mongoose";
import dotenv from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());
// To support JSON-encoded bodies.
//Loading Middleware:
// handling Headers :- this method is used to handle the headers of the request
app.use(cors());
app.use(bodyParser.json());
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");
    res.header("Access-Control-Allow-Credentials",true);
    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});

//handlling .env variables :- this method is used to handle the .env variables
const jwtsecret = process.env.JWT;


//this method is used to verify authentication of the user
//by checking the token in the header


const Authentication = async (req, res, next) => {
    let token = req.header('x-access-token');

    //verify the JWT token:
    jwt.verify(token, jwtsecret, (err, decoded) => {
        if (err) {
            //Not valid JWT token.
            //stop the execution of the function and send a 401 (Unauthorized) status code.
            return res.status(401).send(err);
        } else {
            //if the token is valid :
            //get the user id from the decoded token:
            req.user_id = decoded._id;
            next();
        }
    });
}


//Method to verify the token validity :

const CheckSession = function (req, res, next) {

    //get the refresh token from the header
    let refresh_Token = req.header('x-refresh-token');
    //Get Id of the user from the header:
    let _id = req.header('_id');
    User.findByToken(_id, refresh_Token).then((user) => {
try {
    if (!user) {
        return res.send({"message": "User not found"});
    }
    //if is founded :
    req.user_id = user._id;
    req.refresh_Token = refresh_Token;
    req.userObject = user;
    let isValideSession = false;
    console.log(user.sessions);
    user.sessions.forEach((session) => {

        if (session.token === refresh_Token) {

            //check if the sessions is expired

            if (User.IsRefreshTokenExpired(session.expires) === false) {
                //refresh token is not expired 

                isValideSession = true;
            }
        }
    })
    if (isValideSession) {
        // the session is valid call next() and continue
        next();
    } else {
        return Promise.reject("Invalid Session");
    }

} catch (error) {
    res.status(404).send(error);
}
        
    }).catch((error) => {
        
        res.status(401).send(error);
    })

}

//Loading Models:
import List from "./db/Models/List.js";
import Task from "./db/Models/Task.js";
import User from "./db/Models/User.js";

//Loading Connections:
//handling mongobd database
dotenv.config();
const Port = process.env.PORT || 3000;
//Connecting to MongoDB :
const connect = async () => {

    try {
        await mongoose.connect(process.env.MONGO);
        console.log("connected to Mongodb")
    } catch (error) {
        throw error;
    }
}
// Test Connection :
mongoose.connection.on("disconnected", () => {

    console.log("mongoDb disconnected")

})
// connected 
mongoose.connection.on("connected", () => {
    console.log("mongoDb connected");

})

mongoose.Schema.Types.String.checkRequired(v => v != null);



// -------------------------------------------------
/*
ListsRoutes Handlers
*/
//Retrieve All Lists :
app.get("/lists", Authentication, (req, res) => {
    List.find({
        //_idUser: req.user_id
    }).then((lists) => {
        res.send(lists);
    })
}
)
//Create a new List :
app.post("/lists", Authentication, (req, res) => {
    let title = req.body.title;
    let newList = new List({
        title,
        _idUser: req.user_id
    });
    newList.save().then((list) => {
        res.send(list);
    })

})
//Updating a List :
app.put("/lists/:id", Authentication, (req, res) => {
    List.findByIdAndUpdate({ _id: req.params.id, _idUser: req.user_id },
        { $set: req.body },
        { new: true })
        .then(() => { res.send({'message':'Seccessfuly updated'}) })


})
//Deleting a List :
app.delete("/lists/:id", Authentication, (req, res) => {
    List.findByIdAndDelete({ _id: req.params.id, _idUser: req.user_id })
        .then((newlist) => {
            res.send(newlist)
            DeletAllTask(newlist._id)
        })

})
// -----------------End Routes : List--------------------------------
// -------------------------------------------------
/*
ListsRoutes Handlers
*/
//Retrieve All Tasks :
app.get("/lists/:idlist/tasks", Authentication, (req, res) => {
    Task.find({ listid: req.params.idlist })
        .then((tasks) => {
            res.send(tasks);
        })
}
)
//Retrieve a Task :
app.get("/lists/:idlist/tasks/:id", Authentication, (req, res) => {
    Task.findOne({
        _id: req.params.id,
        listid: req.params.idlist
    })
        .then((task) => {
            res.send(task);
        })
})
//Create a new tasks :
app.post("/lists/:idlist/tasks", Authentication, (req, res) => {

    List.findOne({
        _id: req.params.idlist,
        _idUser: req.user_id
    })
        .then((list) => {
            if (list) {
                //valide user authenticated.
                return true;
            }
            //user not authenticated.
            return false;
        }).then((isAuthenticated) => {
            if (isAuthenticated) {
                let newtask = new Task({
                    title: req.body.title,
                    desc:req.body.desc,
                    type:req.body.type,
                    dueDate:req.body.dueDate,
                    listid: req.params.idlist
                });
                newtask.save().then((task) => {
                    res.send(task);
                })
            }else{
                res.sendStatus(404);
            }
        })



})
//Updating a Task :
app.put("/lists/:idlist/tasks/:id", Authentication, (req, res) => {
    List.findOne({
        _id: req.params.idlist,
        _idUser: req.user_id
    }).then((list) => {
            if (list) {
                //valide user authenticated.
                return true;
            }
            //user not authenticated.
            return false;
        }).then((isAuthenticated) => {
            if (isAuthenticated) {
        Task.findByIdAndUpdate({
            _id: req.params.id,
            listid: req.params.idlist
        },
            { $set: req.body },
            { new: true })
            .then(() => { res.send({ message: "Updated seccessfully" }) })
            
            }else{
                res.sendStatus(404).send({ message: "not authenticated" });
            }
        })
        
  
})
//Deleting a List :
app.delete("/lists/:idlist/tasks/:id",Authentication, (req, res) => {
    List.findOne({
        _id: req.params.idlist,
        _idUser: req.user_id
    }).then((list) => {
            if (list) {
                //valide user authenticated.
                return true;
            }
            //user not authenticated.
            return false;
        }).then((isAuthenticated) => {
            if (isAuthenticated) {
                Task.findByIdAndDelete({
                    _id: req.params.id,
                    listid: req.params.idlist
                })
                    .then((newlist) => { res.send(newlist) })
            
            }else{
                res.sendStatus(404);
            }
        })
   

})
// -------------------------------------------------
/*
ListsRoutes Handlers
*/
// Creating a new User :
app.post("/users", (req, res) => {
    let user = req.body;
    //let newUser = new User({user});
    let newUser = new User(user);

    newUser.save().then(() => {
        return newUser.createSession().then((refreshToken) => {


            return newUser.generateAuthToken().then((accesstoken) => {

                return { accesstoken, refreshToken };
            })
        })
    })
        .then((tokens) => {

            res
                .header("x-refresh-token", tokens.refreshToken)
                .header("x-access-token", tokens.accesstoken)
                .send(newUser);

        }).catch((error) => {
            res.status(400).send(error);
        })

})

//Signing in :
app.post("/users/login", (req, res) => {
    let email = req.body.email;
    let password = req.body.password;
    User.findByAccess(email, password).then((user) => {
        if(user){
           
            return user.createSession().then((refreshToken) => {
                //session created
                //generate token
                return user.generateAuthToken().then((accesstoken) => {
                    
                    //token generated and returned
                    return { accesstoken, refreshToken }
                }).then((tokens) => {
                    res
                        .header("x-refresh-token", tokens.refreshToken)
                        .header("x-access-token", tokens.accesstoken)
                        .send(user);

                }).catch((error) => {
                    res.status(400).send(error);
                })
            })
        }else{
            res.status(400).send("Invalid Credentials");
        }
        
    })
})

// when deleting a list, all the tasks in the list are deleted. with
const DeletAllTask = (listid) => {
    Task.deleteMany({ listid: listid }).then(() => {
        console.log("deleted all tasks")
    })
}
//GET the Access Token : retrieve the access token.
app.get("/users/root/access-token", CheckSession, (req, res) => {
    //the user is logged in so we can send the access token.
    req.userObject.generateAuthToken().then((accesstoken) => {
        res.header("x-access-token", accesstoken).send({ accesstoken });
    }).catch((error) => {
        res.status(400).send(error);
    })

})
// ----------------------------------------------------------------


app.listen(Port, () => {
    connect();
    console.log("Server is running on port 3000");
});