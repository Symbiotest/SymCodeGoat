// VULNERABLE: SSRF via scalaj-http
import scalaj.http.Http

object ScalajHttpSSRF {
  def fetchUserData(userInput: String): String = {
    // User input directly used in URL - vulnerable to SSRF
    val response = Http(s"http://api.example.com/data?user=$userInput").asString
    response.body
  }
  
  // Example of safe alternative using whitelist
  def safeFetchUserData(userId: String): Option[String] = {
    val allowedIds = Set("user1", "user2", "user3")
    if (allowedIds.contains(userId)) {
      val response = Http(s"http://api.example.com/data?user=$userId").asString
      Some(response.body)
    } else {
      None
    }
  }
}
