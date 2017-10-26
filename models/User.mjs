import MongoModels from 'mongo-models';
import Bcrypt from 'bcrypt';
import Joi from 'joi';
import uuid from 'node-uuid';

export default class User extends MongoModels {
  constructor(attrs) {
    super(attrs);

    Object.defineProperty(this, '_roles', {
      writable: true,
      enumerable: false,
    });
  }

  static async generatePasswordHash(password) {
    try {
      const salt = await Bcrypt.genSalt(10);
      const hash = await Bcrypt.hash(password, salt);
      return { password, hash };
    } catch (e) {
      console.error(e);
      return new Error('failed to hash password');
    }
  }

  static async create({ username, password, email }) {
    try {
      const passwordHash = await this.generatePasswordHash(password);
      const document = {
        isActive: true,
        username: username.toLowerCase(),
        password: passwordHash.hash,
        email: email.toLowerCase(),
        createdAt: new Date(),
        apiToken: uuid.v4(),
      };
      const user = await new Promise((resolve, reject) => {
        this.insertOne(document, (err, user) => {
          if (err) {
            console.error(err);
            reject(err);
          } else {
            resolve(user);
          }
        });
      });
      return user;
    } catch (e) {
      console.log(e);
      return null;
    }
  }

  static async findByCredentials({ username, password }) {
    try {
      const query = { isActive: true };
      if (username.indexOf('@') > -1) {
        query.email = username.toLowerCase();
      } else {
        query.username = username.toLowerCase();
      }
      const user = await new Promise((resolve, reject) => {
        this.findOne(query, (err, user) => {
          if (err) {
            console.log(err);
            reject(err);
          } else {
            resolve(user);
          }
        });
      });
      if (user) {
        const source = user.password;
        const passwordMatch = await Bcrypt.compare(password, source);
        if (passwordMatch) {
          return user;
        } else {
          return null;
        }
      } else {
        return null;
      }
    } catch (e) {
      console.log(e);
      return null;
    }
  }

  static async findByUsername(username) {
    try {
      const query = { username: username.toLowerCase() };
      const user = await new Promise((resolve, reject) => {
        this.findOne(query, (err, user) => {
          if (err) {
            console.log(err);
            reject(err);
          } else {
            resolve(user);
          }
        });
      });
      return user;
    } catch (e) {
      console.log(e);
      return null;
    }
  }

  canPlayRole(role) {
    if (!this.roles) {
      return false;
    }

    return this.roles.hasOwnProperty(role);
  }
}

User.collection = 'users';

User.schema = Joi.object().keys({
  _id: Joi.object(),
  isActive: Joi.boolean().default(true),
  username: Joi.string()
    .token()
    .lowercase()
    .required(),
  password: Joi.string(),
  email: Joi.string()
    .email()
    .lowercase()
    .required(),
  roles: Joi.object().keys({
    admin: Joi.boolean().default(false),
  }),
  apiToken: Joi.string(),
  resetPassword: Joi.object().keys({
    token: Joi.string().required(),
    expires: Joi.date().required(),
  }),
  createdAt: Joi.date(),
});

//This indexes need to be mannally created
User.indexes = [
  { key: { username: 1, unique: 1 } },
  { key: { email: 1, unique: 1 } },
];
