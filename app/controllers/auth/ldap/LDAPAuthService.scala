package controllers.auth.ldap

import java.util.Hashtable
import javax.naming._
import javax.naming.directory._

import com.google.inject.Inject
import controllers.auth.AuthService
import play.api.Configuration

import scala.util.control.NonFatal

class LDAPAuthService @Inject()(globalConfig: Configuration) extends AuthService {

  private val log = org.slf4j.LoggerFactory.getLogger(classOf[LDAPAuthService])

  private final val config = new LDAPAuthConfig(globalConfig.get[Configuration]("auth.settings"))

  def auth(username: String, password: String): Option[String] = {
    val env = new Hashtable[String, String](11)
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, s"${config.url}")
    env.put(Context.SECURITY_AUTHENTICATION, config.method)

    if (username.contains("@")) {
      env.put(Context.SECURITY_PRINCIPAL, username)
    } else if (!config.domain.isEmpty()){
      env.put(Context.SECURITY_PRINCIPAL, s"$username@${config.domain}")
    } else {
      env.put(Context.SECURITY_PRINCIPAL, config.userformat.format(username,config.baseDN))
    }
    log.debug(s"Logging into LDAP with user ${env.get(Context.SECURITY_PRINCIPAL)}")
    env.put(Context.SECURITY_CREDENTIALS, password)

    try {
      val ctx = new InitialDirContext(env)
      log.debug(s"User ${env.get(Context.SECURITY_PRINCIPAL)} authenticated")

      if (!config.groupDN.isEmpty && !config.groupfilter.isEmpty()) {
        val controls: SearchControls = new SearchControls
        controls.setReturningAttributes(Array[String]("cn"))
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE)

        log.debug(s"Searching group base: ${config.groupDN}")
        log.debug(s"Using group filter: ${config.groupfilter.format(username, config.baseDN)}")

        val answers: NamingEnumeration[SearchResult] = ctx.search(config.groupDN, config.groupfilter.format(username, config.baseDN), controls)
        ctx.close()

        if(answers.hasMore()){
          val result: SearchResult = answers.nextElement
          log.debug(s"Found LDAP result: $result")
        } else {
          throw new AuthenticationException("Empty group search results, access denied")
        }

        if(answers.hasMore())
          throw new AuthenticationException("Too many group search results, expected exactly 1. Adjust your group-filter setting.")

        log.debug(s"User ${env.get(Context.SECURITY_PRINCIPAL)} authorized")
      }

      Some(username)

    } catch {
      case ex: AuthenticationException =>
        log.info(s"login of $username failed with: ${ex.getMessage}")
        None
      case NonFatal(e) =>
        log.error(s"login of $username failed", e)
        None
    }
  }

}
