import User from '../models/User';
import passport from 'koa-passport';
import MongoModels from 'mongo-models';
import { default as LocalStrategy } from 'passport-local';

const validateFunc = async (username, password, done) => {
  MongoModels.connect('mongodb://localhost:27017/aniden', {}, async err => {
    const user = await User.findByCredentials({ username, password });
    if (!user) {
      console.log('Unauthorized');
      return null;
    }

    return done(null, user);
  });
};

passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

passport.use(new LocalStrategy(validateFunc));
