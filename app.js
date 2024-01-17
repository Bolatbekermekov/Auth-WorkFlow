const express = require("express")
const app = express()

// extra security packages

const helmet = require('helmet')
const cors = require("cors")
const xss = require("xss-clean")
const rateLimit = require("express-rate-limit")
const validator = require("validator")
const fileUpload = require('express-fileupload');

const cookieParser = require("cookie-parser")
const connectDb = require('./db/connect')
const notFound = require("./error/not-found")
const CustomAPIError = require("./error/error")
const errorHandler = require("./error/error-handler")
require('dotenv').config()
require('express-async-errors')

//ruotes
const userRouter = require("./routes/userRoutes")
const authRouter = require("./routes/authRoutes")
const productRouter = require('./routes/productRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const orderRouter = require('./routes/orderRoutes');
const morgan = require("morgan")



app.use(morgan('tiny'))
app.use(express.json())
app.use(cookieParser(process.env.JWT_SECRET))
app.use(helmet())
app.use(cors())
app.use(xss())
app.set('trust proxy',1)
app.use(rateLimit({
  windowMs:15 * 60 * 1000,//15minutes
  max:100 //limit each ip to 100 requests per windows 
}))

app.use(express.static('./public'))
app.use(fileUpload())

//Swagger UI
const swaggerUI = require("swagger-ui-express")
const YAML = require('yamljs')
const swaggerDocument = YAML.load('./swagger.yaml')


app.get("/api",(req,res)=>{
  res.send("<h1>Chee Taaam</h1><a href='/api-docs'>Documentation</a>")
})

app.use("/api-docs",swaggerUI.serve,swaggerUI.setup(swaggerDocument))

// app.use(express.static("./public"))
app.use("/api/auth",authRouter)
app.use('/api/users', userRouter);
app.use('/api/products', productRouter);
app.use('/api/reviews', reviewRouter);
app.use('/api/orders', orderRouter);
app.use(errorHandler)
app.use(notFound)
app.use(CustomAPIError)


const port = process.env.PORT || 5000;
const start = async()=>{
  try{ await connectDb(process.env.MONGO_URI)
    app.listen(port,()=>console.log(`app listening on port ${port}`))
  }
  catch(err)
  {console.log(err);}
}
start()
