const CustomError = require('../error/index');
const { isTokenValid } = require('../utils/jwt');
const Token = require('../models/Token');
const { attachCookiesToResponse } = require('../utils/index')
const authenticateUser = async (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies;
  try{
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      console.log(payload);
      req.user = payload.user;
      console.log(req.user);
      return next();
    }
    const payload = isTokenValid(refreshToken);

    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken,
    });

    if (!existingToken || !existingToken?.isValid) {
      throw new CustomError.UnauthenticatedError('Authentication Invalid');
    }

    // attachCookiesToResponse({
    //   res,
    //   user: payload.user,
    //   refreshToken: existingToken.refreshToken,
    // });

    req.user = payload.user;
    next();
  } catch (error) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
}
}

const authorizePermissions = (...role_from_routes) => {
  return (req, res, next) => {
    if (!role_from_routes.includes(req.user.role)) {
      throw new CustomError.UnauthenticatedError(
        'Unauthorized to access this route'
      );
    }
    next();
  };
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};