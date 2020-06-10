/** The MIT License (MIT)
 * Copyright (c) 2016 Julian Lyndon-Smith (julian@whogloo.io), whoGloo inc
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

module.exports = function(app,options) {
  var debug = require('debug')('loopback-jwt');
  var jwt = require('express-jwt');
  var _ = require('lodash');

  if (!options.secretKey) {
      throw new Error("secretKey must be supplied");
  }

  let getToken = (req) => {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.access_token) {
            return req.query.access_token.split(' ')[1];
    }

    return null;
  };

  var data = {
      secretKey: options.secretKey,
      algorithms: ['RS256','HS256'],
      model: options.model || 'User',
      // the only URL we will try to process role mappings on
      roleMappingURL: options.roleMappingURL || '/login',
      roleModel: options.roleModel || 'Role',
      roleMappingModel: options.roleMappingModel || 'RoleMapping',
      identifier: options.identifier || 'email',
      roleIdentifier: options.roleIdentifier || 'app_metadata.authorization.roles',
      roleIdentifierNamespace: options.roleIdentifierNamespace,
      globalTenantId: options.globalTenantId || null,
      tenantId: options.tenantId || null,
      tenantIdentifier: options.tenantIdentifier || 'app_metadata.authorization.groups',
      tenantIdentifierNamespace: options.tenantIdentifierNamespace,
      password: options.password || options.secretKey,
      verify: options.verify || options.verify,
  };

  var checkJwt = jwt({
      algorithms: data.algorithms,
      secret: data.secretKey,
      credentialsRequired: options.credentialsRequired,
      getToken: options.getToken || getToken
  })

  .unless( { path: options.unless || []} );

  var filter;

  var mapUser = function(req,res,next) {

      if (!req.user) {
           debug("no current user context found.");
           next();
           return;
      }

      debug("attempting to map user [%s]",req.user[data.identifier]);

      filter = {
        where: {
          email: req.user[data.identifier]
        },

        include: ['accessTokens']
      };

      if (!!data.roleMappingURL) {
        filter.include.push('roles');
      }

      app.models[data.model].findOne(filter, function(err, user) {

          if (err) {
              debug("find failed",err);
              return next(err);
          }

          let action;
          let accessTokens = user && user.accessTokens();

          if (!user) {
              debug('no user found, creating');
              action = createUser;
          } else if (!accessTokens || accessTokens.length === 0) {
              action = mapRolesAndLoginUser;
              
          } else {
              action = async ()=> {
                  await mapRolesAndLoginUser(req, user);
                  const token = await user.accessTokens.findOne({userId: user.id});
                  debug("Got accessToken from db ", token)
                  return token
              }
          }
          action(req, user)
            .then(function(token) {
                debug(token, user);
                // refresh
                if(token) { 
                  app.models.user.findById(token.userId).then((userReload) => {
                    req.user = userReload;
                    req.accessToken = token;
                    next();
                  }).catch(next); 
                } else {
                  next();
                }
                
            })
            .catch(function(err) {
                next(err);
            });

          
      });
  };

  function getObjectProperty(obj, namespace, path) {
    if (!path) {
      //debug('getObjectProperty(): no path, returning null');
      return null;
    }

    if (typeof path === 'object') {
      parts = path;
    } else {
      parts = path.split('.');
    }

    //debug('getObjectProperty()', obj, namespace, path, parts);
    if (!!namespace && namespace !== '' && parts.length > 0 && obj[namespace + parts[0]]) {
      // remove the namespace prefix
      obj = obj[namespace + parts[0]];
      parts.splice(0, 1);
      //debug('getObjectProperty(): path without namespace', obj, parts);
    }

    if (!obj) {
      //debug('getObjectProperty(): no object to lookup path', parts);
      return null;
    } else if (parts.length === 1) {
      //debug('getObjectProperty(): getting first level property', parts);
      return !!obj[parts[0]] ? obj[parts[0]] : null;
    } else if (parts.length > 1 && typeof obj[parts[0]] == 'object') {
      //debug('getObjectProperty(): going deeper into object', parts);
      return getObjectProperty(obj[parts[0]], null, parts.splice(1));
    }
    //debug('getObjectProperty(): property not found', parts, obj, parts[0], obj[parts[0]], typeof obj[parts[0]]);
    return null;
  }

  function convertUserDBRoleList(user) {
    if(!user.roles) return [];
    return user.roles.map((role) => role.name);
  }

  async function deleteRelation(dbUser, role) {
    if(dbUser.roles().length === 0) { return; }
    // expects a hasManyThrough relationsship
    // when not, try destory instead
    try {
      debug(dbUser);
      debug("Remove role from roles: ", role)
      await dbUser.roles.remove(role); 
      debug(dbUser);
    } catch(e) {
      try {
        debug("Destroy role from roles.")
        await dbUser.roles.destroy(role.id); 
        debug(dbUser);
      } catch(e) {
        debug(e);
      }
    }
  }

  async function deletePrincipalRelations(role, principals) {
    await Promise.all(principals.map(async function (principal) {
      try {
        await role.principals.destroy(principal.id);
      } catch(e) {
        debug(e);
      }
    }));
  }

  async function clearRolesFromUser(dbUser, reqUser) {
    let possibleRoles = await app.models["Role"].find();
    // check if an extra mapping exists between this entities (for easy access)
    const isClientMappedToRole = dbUser.roles() ? true : false;

    await Promise.all(possibleRoles.map(async (possibleRole) => {
      try {
        debug("Check role: ");
        debug(possibleRole);
        let relatedPrincipals = await possibleRole.principals.find({principalType: app.models[data.roleMappingModel].USER,
                                                                  principalId: dbUser.id});
        if(!relatedPrincipals && relatedPrincipcals.length === 0) { return; }
        debug(`Found principals ${possibleRole}: `);
        debug(relatedPrincipals);
  
        await deletePrincipalRelations(possibleRole, relatedPrincipals);


        if(isClientMappedToRole) { 
          debug("After deleting principals: ", possibleRole, dbUser);
          debug(await possibleRole.principals.find({principalType: app.models[data.roleMappingModel].USER,
            principalId: dbUser.id}));
          debug("Begin deleting role relations...")
          await deleteRelation(dbUser, possibleRole);
        }
      } catch(e) {
        debug(e);
      }
    }));
    delete reqUser.roles;
    return dbUser;
  }

  function mapRolesAndLoginUser(req, user) {
    debug('mapping roles and logging in user', req.user, data);

    let validTenant = false;
    let tenantIds = getObjectProperty(req.user, data.tenantIdentifierNamespace, data.tenantIdentifier) || [];
    if (!!tenantIds && !Array.isArray(tenantIds)) {
      tenantIds = [tenantIds];
    }
    debug('checking in tenant IDs', tenantIds, 'for tenant', data.tenantId);
    if (!!data.tenantId || !!data.globalTenantId) {
      if (!!tenantIds && tenantIds.findIndex((t) => t === data.tenantId) !== -1) {
        debug('this user has a valid tenantId for', data.tenantId);
        validTenant = true;
      } else if (!!data.globalTenantId && !!tenantIds && tenantIds.findIndex((t) => t === data.globalTenantId) !== -1) {
        debug('this user has the global tenantId which gives them access to tenantId', data.tenantId);
        validTenant = true;
      } else {
        debug('this user does not have a valid tenantId for', data.tenantId);
      }
    } else {
      debug('tenantId not required');
      validTenant = true;
    }

    return new Promise(async function(resolve, reject) {
      let roles = getObjectProperty(req.user, data.roleIdentifierNamespace, data.roleIdentifier);
      debug('found roles in jwt user to map', roles);
      let u = user.toJSON();

      const dbRoles = convertUserDBRoleList(u);
      if (Array.isArray(roles) && (_.difference(roles, dbRoles).length > 0)) {
        let operations = [];

        // remove roles
        await clearRolesFromUser(user, u);
        debug("User cleared from roles: ");
        debug(user);

        //remove all acc tokens
        //clearAccessTokensFromUser(user);

        // loop through the roles attribute of the user jwt
        for (let roleName of roles) {
          debug('checking for role', roleName, 'in user roles', u.roles);
          let found = false;
          if(!!u.roles){
               for (let r of u.roles) {
                // check to see if the user has the role already
                if (r.name === roleName) {
                  found = true;
                  break;
                }
              }   
          }
          if (!found && validTenant) {
            // add a role create operation to the list
            debug('role not found & tenant valid or not required');
            operations.push(ensureUserHasRole(user.id, roleName));
          } else {
            debug('role found');
          }
        }

        if (operations.length > 0) {
          debug('processing role adds');
          Promise.all(operations).then(function (results) {
            loginUser(req)
              .then(function(token) {
                debug("logged in user [%s]", user.email);
                resolve(token);
              })
              .catch(function(err) {
                debug("login error", err);
                reject(err);
              });
          }, function (err) {
            reject(err);
          });
        } else {
          debug('no role adds needed');
          loginUser(req)
            .then(function(token) {
              debug("logged in user [%s]", user.email);
              resolve(token);
            })
            .catch(function(err) {
              debug("login error", err);
              reject(err);
            });
        }
      } else {
        loginUser(req)
          .then(function(token) {
            debug("logged in user [%s]", user.email);
            resolve(token);
          })
          .catch(function(err) {
            debug("login error", err);
            reject(err);
          });
      }
    });
  }

  function ensureUserHasRole(userId, roleName) {
    debug('ensuring user has role', userId, roleName);
    return new Promise(function(resolve,reject) {
      app.models[data.roleModel].findOne({
        where: {
          name: roleName
        },
        include: ['principals']
      }, function(err, role) {
        if (err) {
          debug('error looking up role', roleName, err);
          return reject(err);
        }

        if (!role) {
          debug('initializing role', roleName);


          app.models[data.roleModel].create({
            name: roleName
          }, function (err, newRole) {
            if (err) {
              debug('error initializing role', err);
              return reject(err);
            }

            debug('initialized role', newRole);
            addUserToRole(userId, newRole).then(function (p) {
              resolve(newRole);
            }).catch((err) => {
              reject(err);
            });
          });
        } else {
          // role already exists
          debug('role already exists', roleName);
          addUserToRole(userId, role).then(function (p) {
            resolve(role);
          }).catch((err) => {
            reject(err);
          });
        }
      });
    });
  }

  function addUserToRole(userId, role) {
    return new Promise(async function(resolve, reject) {
      debug('adding user to role:', userId, role);

      // add the primary superuser to the admin group
      role.principals.create({
        principalType: app.models[data.roleMappingModel].USER,
        principalId: userId
      }, function (err, principal) {
        if (err) {
          debug('error associating role users', err);
          return reject(err);
        }
        debug('associated role users');
        resolve(principal);
      });
    });
  }

  function loginUser(req) {
      let now = Math.round(Date.now().valueOf()/1000);
      debug("Try to perform login for user " + req.user)
      let ttl = req.user.exp - now;
      let email = req.user[data.identifier];

      debug("attempting to login user [%s]",email);

      return new Promise(function(resolve,reject) {

          app.models[data.model].login({
              email,
              password: data.password.toString(),
              ttl
          })

          .then(async function(token) {
              debug("logged in user [%s]",email);
              const user = await app.models[data.model].findOne({where: { email }})
              await app.models.AccessToken.updateAll({id: token.id}, { userId: user.id })
              const updatedToken = await app.models.AccessToken.findById(token.id);
              debug("Resolve with updated usertoken: ", token)
              return resolve(updatedToken);
              return resolve(token);
          })
          
          .catch(function(e) {
              debug("login error",e);
              return reject(e);
          });
      });
  }

   function logout(req, res) {
       app.models[data.model].logout(req.accessToken.id, function(err) {
           res.send(err);
        });
    }

  function getUser(newUserData){
      if(newUserData.id){
          return app.models[data.model].findById(newUserData.id)
              .then((user)=> {
                  if(!user){
                      return app.models[data.model].create(newUserData)
                  }
                  return user.updateAttributes(newUserData).then(()=>user)
              })
      }
      return app.models[data.model].create(newUserData)
  }
  function createUser(req) {
      debug("creating new user");

      var id = req.user[data.identifier];

      // @todo Search for the reason
      // cache user reference because after create a user req.user is null
      var user = req.user;

      return new Promise(function(resolve,reject) {
          let newUserData = {
              email: id,
              password: data.password.toString()
          };

          if (typeof options.beforeCreate === 'function') {
              resolve(
                options.beforeCreate(newUserData,req.user) || newUserData
              );
          } else {
              resolve(newUserData);
          }
      })
      .then(function(newUserData) {


          return getUser(newUserData)
                  .then(function(newUser) {
                      debug("new user created [%s]",newUser.email);
                      req.user = user;
                      return mapRolesAndLoginUser(req, newUser)
                        .then(function (token) {
                          return Promise.resolve(token);
                        });
                  })
                  .catch(function(e) {
                    debug("error creating user",e);
                    return Promise.reject(e);
                  });
      })
      .catch(function(e) {
          debug("error creating user",e);
          return Promise.reject(e);
      });
  }

  var authenticated = [checkJwt,mapUser];

  return {
      authenticated: authenticated,
      logout: logout
  };
};
