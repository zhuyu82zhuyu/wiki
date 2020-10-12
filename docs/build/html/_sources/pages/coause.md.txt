

========================
课件示例 第20课
========================

身份验证是大多数应用程序的重要组成部分。 有许多不同的方法和策略来处理身份验证。 每个项目采用的方法取决于其特定的应用程序要求。 本章将介绍几种可以适应各种不同要求的身份验证方法。为了演示，我们以下面的需求为例，逐步的讲解及实现：

客户端将首先使用用户名和密码进行身份验证。一旦通过身份验证，服务器将发出 JWT，该 JWT 可以在后续请求的授权头中作为 token发送，以验证身份信息。我们还将创建一个受保护的路由，该路由仅对包含有效 JWT 的请求才可访问。

我们将从第一个需求开始：对用户进行身份验证。 然后，我们将通过发布JWT扩展它。 最后，我们将创建一条受保护的路由，以检查请求上的有效JWT。

权限和用户模块
==============
我们将从生成一个 AuthModule 开始，其中有一个 AuthService::

    $ nest g module auth
    $ nest g service auth

当我们实现 AuthService 时，我们会发现在 UsersService 中封装用户操作是很有用的，所以现在让我们生成这个模块和服务::

    $ nest g module users
    $ nest g service users

替换这些生成文件的默认内容，如下所示。 对于我们的示例应用程序，UsersService只需维护一个硬编码的内存中用户列表，以及一个按用户名检索一个的find方法。 在真实的应用中，可以使用选择的库（例如TypeORM，Sequelize，Mongoose等）在其中构建用户模型和持久层。

users/users.service.ts

.. code-block:: TypeScript
    :linenos:

    import { Injectable } from '@nestjs/common';

    export type User = any;

    @Injectable()
    export class UsersService {
    private readonly users: User[];

    constructor() {
        this.users = [
        {
            userId: 1,
            username: 'john',
            password: 'changeme',
        },
        {
            userId: 2,
            username: 'chris',
            password: 'secret',
        },
        {
            userId: 3,
            username: 'maria',
            password: 'guess',
        },
        ];
    }

    async findOne(username: string): Promise<User | undefined> {
        return this.users.find(user => user.username === username);
        }
    }

在UsersModule中，唯一需要做的更改是将UsersService添加到@Module装饰器的exports数组中，以便在此模块外部可见（我们将在AuthService中很快使用它）。

users/users.module.ts

.. code-block:: TypeScript
    :linenos:

    import { Module } from '@nestjs/common';
    import { UsersService } from './users.service';

    @Module({
    providers: [UsersService],
    exports: [UsersService],
    })
    export class UsersModule {}


我们的AuthService负责检索用户并验证密码。 为此，我们创建一个validateUser()方法。 在下面的代码中，我们使用便利的ES6 spread运算符在返回用户对象之前从用户对象中删除password属性。 稍后，我们将通过passport-local策略调用validateUser()方法。

auth/auth.service.ts

.. code-block:: TypeScript
    :linenos:

    import { Injectable } from '@nestjs/common';
    import { UsersService } from '../users/users.service';

    @Injectable()
    export class AuthService {
    constructor(private readonly usersService: UsersService) {}

    async validateUser(username: string, pass: string): Promise<any> {
        const user = await this.usersService.findOne(username);
        if (user && user.password === pass) {
        const { password, ...result } = user;
        return result;
        }
        return null;
    }
    }

注意：
    在实际的应用程序中，不会以纯文本形式存储密码。 取而代之的是使用带有加密单向哈希算法的bcrypt之类的库。 使用这种方法，只需要存储散列密码，然后将存储的密码与输入密码的散列版本进行比较，因此永远不会以纯文本形式存储或公开用户密码。 为了使我们的示例应用程序简单，我们使用纯文本。 不要在您的真实应用中这样做！

现在，我们更新AuthModule以导入UsersModule。

.. code-block:: TypeScript
    :linenos:

    import { Module } from '@nestjs/common';
    import { AuthService } from './auth.service';
    import { UsersModule } from '../users/users.module';

    @Module({
    imports: [UsersModule],
    providers: [AuthService],
    })
    export class AuthModule {}



Passport介绍
================
Passport是最流行的node.js身份验证库，它已成功被用于许多生产应用程序中。 将此工具与 Nest 框架集成起来非常简单，Nest 框架使用 ``@nestjs/passport`` 模块与之对应。 在较高级别，Passport 执行一系列步骤如下：

#. 通过验证用户的”证”(例如：用户名/密码、JSON Web Token( JWT )或其他的身份令牌)来验证用户的身份。
#. 管理身份验证状态（通过发出可移植的令牌（例如JWT）或创建Express会话）
#. 将有关经过身份验证的用户的信息附加到Request对象，以在路由处理程序中进一步使用

Passport具有丰富的策略（strategie）生态系统，可实施各种身份验证机制。 尽管概念上很简单，但是可以选择的Passport策略集很大，并且存在很多变化。 Passport将这些不同的步骤抽象为标准模式，而 ``@nestjs/passport`` 模块将这种模式包装并标准化为熟悉的Nest构造。

在本章中，我们将使用这些功能强大且灵活的模块为RESTful API服务器实现完整的端到端身份验证解决方案。 可以使用此处介绍的概念来实施任何Passport策略，以自定义身份验证方案。 可以按照本章中的步骤构建完整的示例。


身份认证
==========
首先，我们需要安装所需的软件包。 Passport提供了不同的策略，其中一种称为 ``passport-local`` 的策略，该策略实现了"用户名/密码"身份验证机制，这符合我们在这一部分用例中的需求。
::

    $ npm install --save @nestjs/passport passport passport-local
    $ npm install --save-dev @types/passport-local

注意：
    对于您选择的任何Passport策略，将始终需要 ``@nestjs/passport`` 和 ``passport`` 软件包。 然后，需要安装特定于策略的软件包（例如，passport-jwt或passport-local），以实现要构建的特定身份验证策略。 此外，还可以为任何Passport策略安装类型定义，如上面的 ``@types/passport-local`` 所示，它的作用是在编写TypeScript代码时提供了帮助。

Passport策略
====================
现在可以实现身份认证功能了。我们将首先概述用于任何 Passport 策略的流程。将 Passport 本身看作一个框架是有帮助的。框架的优雅之处在于，它将身份验证过程抽象为几个基本步骤，可以根据实现的策略对这些步骤进行自定义。它类似于一个框架，可以通过提供回调函数（在适当的时候Passport调用这些回调函数）形式的自定义参数（作为纯JSON对象）和自定义代码来配置它。 ``@nestjs/passport`` 模块将该框架包装在一个 Nest 风格的包中，使其易于集成到 Nest 应用程序中。下面我们将使用 ``@nestjs/passport`` ，但首先让我们看一下 Passport 是如何工作的。


配置策略
**********
在Passport中，通过提供以下2点来配置策略：

#. 传递特定于该策略的一组选项。例如，在JWT策略中，可以提供一个密钥来对令牌进行签名。
#. 重写validate()回调方法。在回调方法里可以告诉 Passport 如何与“用户存储”交互(用户存储可以管理用户帐户)。在这里，验证用户是否存在(或创建一个新用户)，以及它们的凭据是否有效。Passport 库期望这个回调在验证成功时返回完整的用户消息，在验证失败时返回 null(失败定义为用户没有找到，或者在使用 passport-local 的情况下，密码不匹配)。。

使用 ``@nestjs/passport`` 通过扩展PassportStrategy类来配置Passport策略。 可以通过在子类中调用super()方法来传递策略选项（上述项目1），还可以选择传入options对象。 可以通过在子类中实现validate()方法来提供verify回调（上面的项目2）。



Passport local策略
**********************

现在，我们可以实施passport-local身份验证策略。 在auth文件夹中创建一个名为local.strategy.ts的文件，并添加以下代码：

.. code-block:: TypeScript
    :linenos:

    import { Strategy } from 'passport-local';
    import { PassportStrategy } from '@nestjs/passport';
    import { Injectable, UnauthorizedException } from '@nestjs/common';
    import { AuthService } from './auth.service';

    @Injectable()
    export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly authService: AuthService) {
        super();
    }

    async validate(username: string, password: string): Promise<any> {
        const user = await this.authService.validateUser(username, password);
        if (!user) {
        throw new UnauthorizedException();
        }
        return user;
    }
    }

对于所有Passport策略，我们都遵循了前面介绍的方法。在使用passport-local的用例中，没有配置选项，因此我们的构造函数仅调用super()，而没有选项对象。

我们还实现了validate()方法。对于每种策略，Passport将使用适当的策略特定的参数集调用validate()方法。对于passport-local策略，Passport希望使用带有以下签名的validate()方法：validate(username: string, password: string):any。

大多数验证工作都在我们的AuthService中完成（借助于UserService），因此方法非常简单。任何Passport策略的validate()方法将遵循类似的模式，仅在表示凭据的方式细节方面有所不同。如果找到了用户并且凭据有效，则将返回用户，以便Passport可以完成其任务（例如在Request对象上创建user属性），并且请求处理管道可以继续。如果找不到，我们将抛出一个异常并让我们的异常层处理它。

通常，每种策略的 validate() 方法的惟一显著差异是如何确定用户是否存在和是否有效。例如，在 JWT 策略中，根据需求，我们可以评估解码令牌中携带的 userId 是否与用户数据库中的记录匹配，或者是否与已撤销的令牌列表匹配。因此，这种子类化和实现特定于策略验证的模式是一致的、优雅的和可扩展的。

我们需要配置 AuthModule 来使用刚才定义的 Passport 特性。更新auth/auth.module.ts。看起来像这样:

.. code-block:: TypeScript
    :linenos:

    import { Module } from '@nestjs/common';
    import { AuthService } from './auth.service';
    import { UsersModule } from '../users/users.module';
    import { PassportModule } from '@nestjs/passport';
    import { LocalStrategy } from './local.strategy';

    @Module({
    imports: [UsersModule, PassportModule],
    providers: [AuthService, LocalStrategy],
    })
    export class AuthModule {}


内置Passport守卫
----------------------
Guards一章介绍了Guards的主要功能：确定是否由路由程序处理请求。事实仍然如此，我们将很快使用该标准功能。 但是，在使用 ``@nestjs/passport`` 模块的情况下，我们还将引入一些新的模块，起初可能会造成混淆，所以现在让我们进行讨论。 从身份验证的角度考虑，用户的应用可以处于2种状态：

#. 用户/客户端 未登录（未认证）
#. 用户/客户端 已登录（已验证）

在第一种情况下（未登录），我们需要执行两个不同的功能：

#. 限制未经身份验证的用户可以访问的路由（即拒绝访问受限制的路由）。 通过将Guard放在受保护的路由上，我们将使用Guards来处理此功能。 将在此Guard中检查是否存在有效的JWT，因此，一旦我们成功发布JWT，我们将在以后使用此Guard。
#. 当以前未经身份验证的用户尝试登录时，启动身份验证步骤。这时我们向有效用户发出 JWT 的步骤。考虑一下这个问题，我们知道需要 POST username/password 凭证来启动身份验证，所以我们将设置 POST /auth/login 路径来处理这个问题。这就提出了一个问题：在这条路由上，我们究竟如何实施“passport-local”策略？

答案很简单：使用另一种略有不同的Guard。 ``@nestjs/passport`` 模块为我们提供了一个内置的Guard来为我们执行此操作。 该Guard调用Passport策略并启动上述步骤（检索凭据，运行验证功能，创建用户属性等）。

上面列举的第二种情况(登录用户)仅仅依赖于我们已经讨论过的标准类型的Guard守卫，以便为登录用户启用对受保护路由的访问。

登录路由
-----------
有了这个策略，我们现在就可以实现一个简单的 /auth/login 路由，并应用内置的Guard来启动passport-local策略流程。

打开 app.controller.ts 文件，并将其内容替换为以下内容：

.. code-block:: TypeScript
    :linenos:

    import { Controller, Request, Post, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';

    @Controller()
    export class AppController {
    @UseGuards(AuthGuard('local'))
    @Post('auth/login')
    async login(@Request() req) {
        return req.user;
    }
    }


通过@UseGuards(AuthGuard('local'))，我们使用了AuthGuard，当我们扩展passport-local策略时， ``@nestjs/passport`` 会自动为我们提供。让我们分解一下。我们的passport-local策略的默认名称为“ local”。我们在@UseGuards（）装饰器中引用该名称，以将其与passport-local包提供的代码关联。如果我们的应用程序中有多个Passport策略（每个策略都可能提供特定于策略的AuthGuard），则用于区分要调用的策略。尽管到目前为止，我们只有一个这样的策略，但不久之后我们将添加第二个策略，因此这对于消除歧义是必需的。

为了测试我们的路由，我们将使用/auth/login路由暂时返回用户。这也让我们演示了Passport的另一个功能：Passport根据我们从validate（）方法返回的值自动创建一个用户对象，并将其作为req.user分配给Request对象。稍后，我们将其替换为代码以创建并返回JWT。

由于这些是API路由，因此我们将使用常用的cURL库对其进行测试。也可以使用在UsersService中硬编码的任何用户对象进行测试::

    $ # POST to /auth/login
    $ curl -X POST http://localhost:3000/auth/login -d '{"username": "john", "password": "changeme"}' -H "Content-Type: application/json"
    $ # result -> {"userId":1,"username":"john"}


Passport jwt策略
*******************

我们已经准备好进入JWT部分的认证系统。让我们回顾并完善我们的需求:

#. 允许用户使用用户名/密码进行身份验证，并返回JWT以用于随后对受保护的API端点的调用。 我们正在努力满足这一要求。 要完成它，我们需要编写发出JWT的代码。
#. 创建基于有效JWT作为承载令牌受到保护的API路由

JWT功能
-----------
我们需要安装更多的包来支持我们的 JWT 需求::

    $ npm install @nestjs/jwt passport-jwt
    $ npm install @types/passport-jwt --save-dev


@nestjs/jwt 包是一个实用程序包，提供 jwt 的相关操作。passport-jwt 包是实现 JWT 策略的 Passport包，@types/passport-jwt 提供 TypeScript 类型定义。

让我们仔细看看如何处理 POST /auth/login 请求。我们使用passport-local策略提供的内置AuthGuard 来装饰路由。这意味着:

#. 仅当用户通过验证后，才会调用路由处理程序
#. req参数将包含一个user用户属性（在passport-local身份验证流期间由Passport填充）

考虑到这一点，我们现在可以最终生成一个真实的JWT，并在此路由中将其返回。 为了使我们的服务保持模块化，我们将在authService中处理生成JWT。 打开auth文件夹中的auth.service.ts文件，并添加login（）方法，并导入JwtService，如下所示：

.. code-block:: TypeScript
    :linenos:

    import { Injectable } from '@nestjs/common';
    import { UsersService } from '../users/users.service';
    import { JwtService } from '@nestjs/jwt';

    @Injectable()
    export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService
    ) {}

    async validateUser(username: string, pass: string): Promise<any> {
        const user = await this.usersService.findOne(username);
        if (user && user.password === pass) {
        const { password, ...result } = user;
            return result;
        }
        return null;
    }

    async login(user: any) {
        const payload = { username: user.username, sub: user.userId };
        return {
            access_token: this.jwtService.sign(payload),
            };
        }
    }

我们使用 @nestjs/jwt 库，该库提供了一个 sign() 函数，用于从用户对象属性的子集生成 jwt，然后以简单对象的形式返回一个 access_token 属性。注意:我们选择 sub 的属性名来保持我们的 userId 值与JWT 标准一致。不要忘记将 JwtService 提供者注入到 AuthService中。

配置JwtModule
------------------------
现在，我们需要更新 AuthModule 来导入新的依赖项并配置 JwtModule。

首先，在auth文件夹下创建 auth/constants.ts，并添加以下代码:

.. code-block:: TypeScript
    :linenos:

    export const jwtConstants = {
        secret: 'secretKey',
    };

我们将使用它在 JWT 签名和验证步骤之间共享密钥。

不要公开此密钥。我们在这里这样做是为了清楚地说明代码在做什么，但是在生产系统中，必须使用适当的措施来保护这个密钥，比如机密库、环境变量或配置服务。

现在，在auth文件夹下更新auth.module.ts文件:

.. code-block:: TypeScript
    :linenos:

    import { Module } from '@nestjs/common';
    import { AuthService } from './auth.service';
    import { LocalStrategy } from './local.strategy';
    import { UsersModule } from '../users/users.module';
    import { PassportModule } from '@nestjs/passport';
    import { JwtModule } from '@nestjs/jwt';
    import { jwtConstants } from './constants';

    @Module({
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.register({
        secret: jwtConstants.secret,
        signOptions: { expiresIn: '60s' },
        }),
    ],
    providers: [AuthService, LocalStrategy],
    exports: [AuthService],
    })
    export class AuthModule {}


我们使用 register() 配置 JwtModule ，并传入一个配置对象。

现在我们可以更新 /auth/login 路径来返回 JWT 。

.. code-block:: TypeScript
    :linenos:

    import { Controller, Request, Post, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    import { AuthService } from './auth/auth.service';

    @Controller()
    export class AppController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(AuthGuard('local'))
    @Post('auth/login')
    async login(@Request() req) {
        return this.authService.login(req.user);
    }
    }

我们继续使用 cURL 测试我们的路由。也可以使用 UsersService 中硬编码的任何用户对象进行测试。

::

    $ # POST to /auth/login
    $ curl -X POST http://localhost:3000/auth/login -d '{"username": "john", "password": "changeme"}' -H "Content-Type: application/json"
    $ # result -> {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
    $ # Note: above JWT truncated


实现Passport JWT
----------------------
现在，我们可以满足我们的最终需求：通过要求请求中包含有效的JWT来保护端点。 Passport也可以在这里帮助我们，它提供了用于通过JSON Web令牌保护RESTful端点的password-jwt策略。 首先在auth文件夹中创建一个名为jwt.strategy.ts的文件，然后添加以下代码：

.. code-block:: TypeScript
    :linenos:

    import { ExtractJwt, Strategy } from 'passport-jwt';
    import { PassportStrategy } from '@nestjs/passport';
    import { Injectable } from '@nestjs/common';
    import { jwtConstants } from './constants';

    @Injectable()
    export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor() {
        super({
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: false,
        secretOrKey: jwtConstants.secret,
        });
    }

    async validate(payload: any) {
        return { userId: payload.sub, username: payload.username };
    }
    }


对于我们的 JwtStrategy ，我们遵循了前面描述的所有 Passport 策略的相同配置。这个策略需要一些初始化，因此我们通过在 super() 调用中传递一个 options 对象来实现。在我们的例子中，这些选项是:

* jwtFromRequest 提供从请求中提取 JWT 的方法。我们将使用在 API 请求的授权头中提供token的标准方法。这里描述了其他选项。
* ignoreExpiration 为了明确起见，我们选择默认的 false 设置，它将确保 JWT 尚未过期的责任委托给 Passport 模块。这意味着，如果我们的路由提供了一个过期的 JWT ，请求将被拒绝，并发送 401 未经授权的响应。Passport会自动为我们办理。
* secretOrKey 我们正在使用权宜之计，即提供对称机密来对令牌进行签名。其他选项（例如，PEM编码的公共密钥）可能更适合生产应用程序。在任何情况下，如前所述，请勿公开此秘密。
* validate() 方法值得讨论一下。对于 JWT 策略，Passport 首先验证 JWT 的签名并解码 JSON。然后调用我们的 validate() 方法，该方法将解码后的 JSON 作为其单个参数传递。根据 JWT 签名的工作方式，我们可以确保我们收到的是先前已签名并颁发给有效用户的有效token令牌。

因此，我们对 validate() 回调的响应很简单，我们只是返回一个包含 userId 和 username 属性的对象。再次回忆一下，Passport 将基于 validate() 方法的返回值构建一个user 对象，并将其作为属性附加到请求对象上。

同样值得指出的是，这种方法为我们留出了将其他业务逻辑注入流程的空间(就像”挂钩”一样)。例如，我们可以在 validate() 方法中执行数据库查询，以提取关于用户的更多信息，从而在请求中提供更丰富的用户对象。这也是我们决定进行进一步验证令牌的地方，例如在已撤销的令牌列表中查找 userId ，使我们能够执行令牌撤销。我们在示例代码中实现的模型是一个快速的 "无状态JWT" 模型，其中根据有效 JWT 的存在立即对每个 API 调用进行授权，并在请求管道中提供关于请求者(其 userid 和 username)的少量信息。

注册JwtModule
-----------------

在 AuthModule 中添加新的 JwtStrategy 作为提供者:

.. code-block:: TypeScript
    :linenos:

    import { Module } from '@nestjs/common';
    import { AuthService } from './auth.service';
    import { LocalStrategy } from './local.strategy';
    import { JwtStrategy } from './jwt.strategy';
    import { UsersModule } from '../users/users.module';
    import { PassportModule } from '@nestjs/passport';
    import { JwtModule } from '@nestjs/jwt';
    import { jwtConstants } from './constants';

    @Module({
    imports: [
        UsersModule,
        PassportModule,
        JwtModule.register({
        secret: jwtConstants.secret,
        signOptions: { expiresIn: '60s' },
        }),
    ],
    providers: [AuthService, LocalStrategy, JwtStrategy],
    exports: [AuthService],
    })
    export class AuthModule {}


通过导入 JWT 签名时使用的相同密钥，我们可以确保 Passport 执行的验证阶段和 AuthService 执行的签名阶段使用同样的密钥。

实现受保护的路由和 JWT 策略保护，我们现在可以实现受保护的路由及其相关的保护。

打开 app.controller.ts 文件，更新如下:

.. code-block:: TypeScript
    :linenos:

    import { Controller, Get, Request, Post, UseGuards } from '@nestjs/common';
    import { AuthGuard } from '@nestjs/passport';
    import { AuthService } from './auth/auth.service';

    @Controller()
    export class AppController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(AuthGuard('local'))
    @Post('auth/login')
    async login(@Request() req) {
        return this.authService.login(req.user);
    }

    @UseGuards(AuthGuard('jwt'))
    @Get('profile')
    getProfile(@Request() req) {
        return req.user;
    }
    }

同样，我们将应用在配置 passport-jwt 模块时 ``@nestjs/passport`` 模块自动为我们提供的 AuthGuard 。这个保护由它的默认名称 jwt 引用。当我们请求GET /profile 路由时，保护程序将自动调用我们的 passport-jwt 自定义配置逻辑，验证 JWT ，并将用户属性分配给请求对象。

确保应用程序正在运行，并使用 cURL 测试路由::

    $ # GET /profile
    $ curl http://localhost:3000/profile
    $ # result -> {"statusCode":401,"error":"Unauthorized"}

    $ # POST /auth/login
    $ curl -X POST http://localhost:3000/auth/login -d '{"username": "john", "password": "changeme"}' -H "Content-Type: application/json"
    $ # result -> {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vybm... }

    $ # GET /profile using access_token returned from previous step as bearer code
    $ curl http://localhost:3000/profile -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2Vybm..."
    $ # result -> {"userId":1,"username":"john"}


注意，在 AuthModule 中，我们将 JWT 配置为 60 秒过期。这个过期时间可能太短了，而处理令牌过期和刷新的细节超出了本文的范围。然而，我们选择它来展示JWT 的一个重要功能和 passport-jwt策略。如果在验证之后等待 60 秒再尝试 GET /profile 请求，将收到 401 未授权响应。这是因为 Passport 会自动检查 JWT 的过期时间，从而省去了在应用程序中这样做的麻烦。

我们现在已经完成了 JWT 身份验证实现。JavaScript 客户端(如 Angular/React/Vue )和其他 JavaScript 应用程序现在可以安全地与我们的 API 服务器进行身份验证和通信。

默认策略
==========

在我们的 AppController 中，我们需要在 @AuthGuard() 装饰器中传递策略的名称。因为我们已经使用了两种 Passport 策略(passport-local 和 passport-jwt)，这两种策略都提供了各种 Passport 组件的实现。传递名称可以消除歧义。当应用程序中包含多个策略时，我们可以声明一个默认策略，这样如果使用该默认策略，我们就不必在 @AuthGuard 装饰器中传递名称。下面介绍如何在导入 PassportModule 时注册默认策略。这段代码将更新进入 AuthModule :

要确定默认策略行为，可以注册 PassportModule 。

.. code-block:: TypeScript
    :emphasize-lines: 12
    :linenos:

    import { Module } from '@nestjs/common';
    import { AuthService } from './auth.service';
    import { LocalStrategy } from './local.strategy';
    import { UsersModule } from '../users/users.module';
    import { PassportModule } from '@nestjs/passport';
    import { JwtModule } from '@nestjs/jwt';
    import { jwtConstants } from './constants';
    import { JwtStrategy } from './jwt.strategy';

    @Module({
    imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
        secret: jwtConstants.secret,
        signOptions: { expiresIn: '60s' },
        }),
        UsersModule
    ],
    providers: [AuthService, LocalStrategy, JwtStrategy],
    exports: [AuthService],
    })
    export class AuthModule {}


自定义 Passport
====================

可以使用register()方法以相同的方式传递任何标准Passport定制选项。 可用选项取决于正在实施的策略。 例如::

    PassportModule.register({ session: true });

还可以在策略的构造函数中传递一个 options 对象来配置它们。例如passport-local策略:

.. code-block:: TypeScript
    :linenos:

    constructor(private readonly authService: AuthService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
        });
    }

命名策略
==========
在实现策略时，可以通过向 PassportStrategy 函数传递第二个参数来为其提供名称。如果你不这样做，每个战略将有一个默认的名称(例如，”jwt”的 jwt策略 )::

    export class JwtStrategy extends PassportStrategy(Strategy, 'myjwt')

然后，通过一个像 @AuthGuard('myjwt') 这样的装饰器来引用它。

