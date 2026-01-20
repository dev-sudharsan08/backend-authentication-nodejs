await User.findOne({$or: [{ name} , { email}]})
await User.findOne().or([{name}, {email}])

const userSchema = new mongoose.Schema({
  user: String,
  email: {
    type: String,
    require: true,
    
  }
})