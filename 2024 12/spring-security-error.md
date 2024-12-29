# 개요
Spring Security 사용 중에 발생하는 에러 해결 기록

# 기존 구현 코드

## SecurityConfig

```kotlin

@Configuration
@EnableMethodSecurity
class SecurityConfig (
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
    private val customAuthenticationEntryPoint: CustomAuthenticationEntryPoint,
    private val customAccessDeniedHandler: CustomAccessDeniedHandler
){

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorization -> authorization
                .requestMatchers( "/actuator/**", "/error/**", "/auth/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/docs/**", "/swagger-resources/**").permitAll()
                .anyRequest().authenticated()
            }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
            .csrf{
                it.disable()
            }
            .exceptionHandling { exceptions ->
                exceptions
                    .authenticationEntryPoint(customAuthenticationEntryPoint)
                    .accessDeniedHandler(customAccessDeniedHandler)
            }
        return http.build()
    }

}

```

## 회원가입 및 로그인 API

로그인은 spring security 를 사용하지 않고 일반 API에서 동작하게 함

```kotlin
@RestController
@RequestMapping("/auth")
class AuthController (
    val userService: UserService,
    val userActivityLogService: UserActivityLogService
) {

    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    fun signUp(@RequestBody signupRequest: SignupRequest) {
        val user = userService.createUser(signupRequest)
        userActivityLogService.createSignUpLog(user.id, user.email)
    }

    @PostMapping("/login")
    fun login(@RequestBody loginRequest: LoginRequest): String {
        val loginSuccessResponse = userService.login(loginRequest)
        userActivityLogService.createLoginLog(loginSuccessResponse.userId, loginSuccessResponse.email)
        return loginSuccessResponse.token
    }
}
```

```kotlin
@Service
@Transactional(readOnly = true)
class UserService (
    private val jwtManager: JwtManager,
    private val userRepository: UserRepository
){

    @Transactional
    fun createUser(signupRequest: SignupRequest): User {
        if (userRepository.existsByEmail(signupRequest.email)) {
            throw RuntimeException("Email already exists")
        }
        val user = User(
            email = signupRequest.email,
            password = encodePassword(signupRequest.password),
            name = signupRequest.name,
            userRole = signupRequest.role ?: UserRole.MEMBER
        )
        return userRepository.save(user)
    }

    fun login(loginRequest: LoginRequest) : LoginSuccessResponse {
        val user = userRepository.findByEmail(loginRequest.email) ?: throw InvalidEmailOrPasswordException()
        if (!matchesPassword(loginRequest.password, user.password)) {
            throw InvalidEmailOrPasswordException()
        }
        val token = jwtManager.generateToken(user.id, user.email, user.userRole.name)
        return LoginSuccessResponse(user.id, user.email, token)
    }

    fun getUserById(userId: String): User {
        return userRepository.findByIdOrThrow(userId)
    }

}
```

여기서 로그인을 하면 문제 없이 jwt를 돌려 받음

### 요청 예시

```json
{
    "email": "admin123@gmail.com",
    "password": "123"
}
```

### 응답 예시

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIzMWVjYWU3Yy03NzZmLTQ0NTEtOTQ5My03MGZlOTk3ZTZkYjQiLCJlbWFpbCI6ImFkbWluMTIzQGdtYWlsLmNvbSIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTczNTQ1NDIxMywiZXhwIjoxNzM1NTQwNjEzfQ.wOywGUdcBiVJ8Y8Qfi5xR63q-J4Nwr8IVlTXM_CSq6M
```

# 403 error 문제 발생

동기적 응답을 사용하는 모든 API에서는 403 에러가 뜨지 않으나,
Streaming 응답을 돌려주는 API 한 군에서 403 에러가 발생하는 것을 확인함

## 문제 발생 지점

```kotlin
@PreAuthorize("hasAnyRole('ADMIN', 'MEMBER')")
@PostMapping
@ResponseStatus(HttpStatus.CREATED)
fun createChat(
    @AuthenticationPrincipal principal: CustomPrincipal,
    @RequestParam model: String = "gpt-4o-mini",
    @RequestParam isStreaming: Boolean = false,
    @RequestBody chatRequest: ChatRequest
): Flux<ServerSentEvent<String>> {
    val userId = principal.userId
    val question = chatRequest.question
    val responseStream = chatService.createAnswer(userId, model, isStreaming, question)

    responseStream
        .mapNotNull { it.data() }
        .collectList()
        .doOnSuccess { answers ->
            val fullAnswer = answers.joinToString("")
            handleChatCompletion(userId, question, fullAnswer)
        }
    return responseStream
}

```

```kotlin
    fun createAnswer(userId: String, model: String, isStreaming: Boolean, question: String): Flux<ServerSentEvent<String>> {
        val responseStream: Flux<ServerSentEvent<String>>
        if (isStreaming) {
            responseStream = openaiApiSender.sendRequestAndStreamResponse(question, model)
                .doOnNext { data -> println("Data: $data") }
                .doOnComplete { println("Stream complete for client") }
                .doOnCancel { println("Stream cancelled by client") }
                .delayElements(Duration.ofMillis(50))
                .map { data ->
                    val answerStream = extractAnswerFromResponseStream(data)
                    ServerSentEvent.builder<String>().data(answerStream).build()
                }
        } else {
            responseStream = Flux.just(openaiApiSender.sendRequestAndGetResponse(question, model))
                .doOnNext { data -> println("Data: $data") }
                .map { data ->
                    val answer = extractAnswerFromResponse(data)
                    ServerSentEvent.builder<String>().data(answer).build()
                }
        }

        return responseStream
    }
```


### 요청 예시
```json
{
    "question" : "2+2는 뭐야?"
}
```

### 응답 예시

```
data:

data:2

data: +

data: 

data:2

data:는

data: 

data:4

data:입니다

data:.

data:

data:

```

### 에러 로그

```
2024-12-29T16:26:16.650+09:00 ERROR 12464 --- [nio-8080-exec-3] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] threw exception
org.springframework.security.authorization.AuthorizationDeniedException: Access Denied
2024-12-29T16:26:16.658+09:00 ERROR 12464 --- [nio-8080-exec-3] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Unable to handle the Spring Security Exception because the response is already committed.] with root cause
org.springframework.security.authorization.AuthorizationDeniedException: Access Denied
2024-12-29T16:26:16.673+09:00 ERROR 12464 --- [nio-8080-exec-3] s.e.ErrorMvcAutoConfiguration$StaticView : Cannot render error page for request [null] as the response has already been committed. As a result, the response may have the wrong status code.
```

이렇게 알 수 없는 이유로 AuthorizationDeniedException이 발생하고
그 때문에 dispatcherServlet 에러가 발생함.   
트랜잭션 커밋이 되지 않아서 chat이 저장되지 않는 문제가 발생함

**즉, 뜬금 없이 발생한 AccessDenied 에러 때문에 비즈니스 로직이 동작하지 않는 상황**


## 동기 요청의 경우

Role 통과가 안 된 것 아닌가? 라고 물어볼 수 있지만
PreAuthorize 에서 Role 때문에 막혔으면 애초에 ResponseStream을 클라이언트에서 받지 못하는 것이 정상임  
현재는 요청은 통과되어 서비스 로직이 동작하지만 response를 돌려주는 과정에서 access denied가 발생하는 것


아래와 같이 동기 요청으로 구현하면 403 에러가 뜨지 않음

```kotlin
    @PreAuthorize("hasAnyRole('ADMIN', 'MEMBER')")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun createChat(
        @AuthenticationPrincipal principal: CustomPrincipal,
        @RequestParam model: String = "gpt-4o-mini",
        @RequestParam isStreaming: Boolean = false,
        @RequestBody chatRequest: ChatRequest
    ): String {
        val userId = principal.userId
        val question = chatRequest.question
        val answer = chatService.createAnswer(userId, model, isStreaming, question)
        handleChatCompletion(userId, question, answer)
        return answer
    }

    private fun handleChatCompletion(userId: String, question: String, fullAnswer: String) {
        val chat = chatService.createChat(userId, question, fullAnswer)
        val user = userService.getUserById(userId)
        userActivityLogService.createChatCreationLog(userId, user.email)
        chatLogService.createChatLog(chat, user)
    }

```


```kotlin
    fun createAnswer(userId: String, model: String, isStreaming: Boolean, question: String): String {
        val response = openaiApiSender.sendRequestAndGetResponse(question, model)
        val answer = extractAnswerFromResponse(response)
    
        return answer
    }
```

### 요청 예시

```json
{
    "question" : "2+2는 뭐야?"
}
```

### 응답 예시

```
2 + 2는 4입니다.
```

## 왜 이런 일이 발생하는걸까?

의심되는 포인트
- spring security 와 spring webflux간의 충돌
- spring security 자체적으로 설정이 잘못됨

# Spring Security의 문제 찾기

spring security 설정에서부터 문제가 있지 않을까 의심함.  
일단 비동기 요청 컨트롤러는 오로지 동기적으로만 동작하도록 변경함.  

```kotlin
    @PreAuthorize("hasAnyRole('ADMIN', 'MEMBER')")
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun createChat(
        @AuthenticationPrincipal principal: CustomPrincipal,
        @RequestParam model: String = "gpt-4o-mini",
        @RequestParam isStreaming: Boolean = false,
        @RequestBody chatRequest: ChatRequest
    ): String {
        val userId = principal.userId
        val question = chatRequest.question
        val answer = chatService.createAnswer(userId, model, isStreaming, question)
        handleChatCompletion(userId, question, answer)
        return answer
    }
```

## Spring Security 에서 exception handling 설정 제거

SecurityConfig 에서 exception handling 설정 제거함.  
원래는 이렇게만 설정해도 로그인은 정상동작하고, 
그 토큰으로 API에 접근할 수 있어야 함

```kotlin
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorization -> authorization
                .requestMatchers( "/actuator/**", "/error/**", "/auth/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/docs/**", "/swagger-resources/**").permitAll()
                .anyRequest().authenticated()
            }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
            .csrf{
                it.disable()
            }
        return http.build()
    }
```

## 관리자 로그인

관리자 계정으로 로그인.

### 로그인 정상 동작

토큰은 정상즉으로 돌아옴

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIzMWVjYWU3Yy03NzZmLTQ0NTEtOTQ5My03MGZlOTk3ZTZkYjQiLCJlbWFpbCI6ImFkbWluMTIzQGdtYWlsLmNvbSIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTczNTQ1ODI1NSwiZXhwIjoxNzM1NTQ0NjU1fQ.r-C3jFZKJ6uuZanUjMiRMk-M8fCqoWKxdyxGQyFSDt4
```

### API 동작도 정상 동작

chat 전체 조회에서 정상 응답 돌아옴

```json
{
  "data": [
    {
      "userId": "31ecae7c-776f-4451-9493-70fe997e6db4",
      "threadId": "67d7e5be-7d59-4b76-9153-3df4cf94f08d",
      "chats": [
        {
          "chatId": "596a389f-6bc7-449c-856f-c8e7aee6e59e",
          "question": "2+1은 뭐야?",
          "answer": "2 + 1은 3입니다.",
          "createdAt": "2024-12-29T07:41:04.159402Z"
        }
      ],
      "createdAt": "2024-12-29T07:41:04.134434Z"
    }
  ]
}
```

## 멤버 계정으로 로그인

### 로그인 정상

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI5MTcxNDUxOS0wMzA1LTQwMjUtODY4Yy0yMjExZDAyZGM2NzEiLCJlbWFpbCI6InNpb253ZXI1QGdtYWlsLmNvbSIsInJvbGUiOiJNRU1CRVIiLCJpYXQiOjE3MzU0NTg0OTMsImV4cCI6MTczNTU0NDg5M30.xz81JXi7WBPTj9DW29jc3arxh8f4darCxwRKii0c8IQ
```

### API 동작

멤버는 chat 전체 조회 권한이 없음  
403 에러가 발생해야하는데, 500 에러가 돌아옴
이건 문제임

```json
{
    "timestamp": "2024-12-29T07:52:58.864415200Z",
    "status": 500,
    "message": "Access Denied"
}
```

