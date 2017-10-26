import './auth';
import passport from 'koa-passport';
import session from 'koa-session';
import route from 'koa-route';
import { default as LocalStrategy } from 'passport-local';
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';

const app = new Koa();
app.keys = ['aniden-session'];
const sessionConfig = {
  maxAge: 86400000,
  overwrite: true,
};
app.use(session(sessionConfig, app));
app.use(bodyParser());
app.use(passport.initialize());
app.use(passport.session());

app.use(
  route.post('/login', (ctx, next) => {
    if (ctx.isAuthenticated()) return next();
    return passport.authenticate('local', (err, user) => {
      if (err || !user) {
        console.log(err);
        return (ctx.status = 401);
      } else {
        ctx.login(user);
        console.log('Login Successfully');
        console.log(ctx.session);
        ctx.body = { status: 'success' };
      }
    })(ctx);
  })
);

app.use(
  route.all('/logout', ctx => {
    console.log('User log out');
    ctx.logout();
    ctx.body = { status: 'sucess' };
  })
);

app.listen(3000, () => {
  console.log('Listen on 3000');
});
