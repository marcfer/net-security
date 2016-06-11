# ================
# Public Functions
# ================
library(XML)
#library(gtools) #rbind.data.frame(xpath1[[1]], xpath1[[2]], ...) --- do.call(rbind.data.frame, xpath1)
#' Function that loads the CWE file into a data frame and returns this data frame
#'
#' @return dataframe with the cwe info
#' @export
#'
#' @examples

parseXMLtoDF <- function() {
  xmlTree <- xmlTreeParse("./data/cwec_v2.9.xml", useInternalNodes = TRUE)
  rootNode <- xmlRoot(xmlTree) #xmlName(rootNode) = Weakness_Catalog
  weaknessesNode <- rootNode[[3]] #weaknessesNode = Weaknesses
  xpath <- xpathApply(weaknessesNode, "//Weakness[@ID<'110']", xmlAttrs)
  dataFrame <- do.call(rbind.data.frame, xpath)
  names(dataFrame) <- c("ID", "Name", "Weakness_Abstraction", "Status")

  xpath2 <- xpathApply(weaknessesNode, "//Weakness[@ID<'110']/Description")
  dataFrame2 <- xmlToDataFrame(xpath2)

  dataFrame3 <- merge(x = dataFrame, y = dataFrame2, by = NULL)

  #Getting CVEs associated (one column data frame with CVEs Associated)
  xpath3 <- xpathApply(weaknessesNode, "//Weakness[@ID<'110']")
  dataFrame4 <- as.data.frame(xmlToDataFrame(xpath3)$Observed_Examples)
  names(dataFrame4) <- c("Associated_CVEs")
  #getCVElistFromText(dataFrame4$Associated_CVEs)

}

#' Title
#'
#' @param id the ID of the CWE as a number
#'
#' @return the Name of the CWE
#' @export
#'
#' @examples getCWENameByID(94) getCWENameByID(102)
getCWENameByID <- function(id) {
  cweDF <- parseXMLtoDF()
  cweDF <- subset(cweDF, ID==id)
  res <- as.character(df$Name)
  return(res)
}



# =================
# Private Functions
# =================

#' Returns a list of CVE from an input string
#'
#' @param string the text from where the CVEs want to be selected
#'
#' @return a list with the CVEs present in the text "string"
#' @export
#'
#' @examples getCVElistFromText(CVE-2009-1936chain: library CVE-2005-3335)
getCVElistFromText <- function(string) {
  return(regmatches(string, gregexpr("[A-Z]{3}-[0-9]{4}-[0-9]{3,10}", string)))
}
