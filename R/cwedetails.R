# ================
# Public Functions
# ================

#' Function that loads the CWE file into a data frame and returns this data frame
#'
#' @return dataframe with the cwe info
#' @export
#'
#' @examples
parseCWEtoDF <- function() {
  xmlTree <- XML::xmlTreeParse("./data/cwec_v2.9.xml", useInternalNodes = TRUE)
  rootNode <- XML::xmlRoot(xmlTree) #xmlName(rootNode) = Weakness_Catalog
  weaknessesNode <- rootNode[[3]] #weaknessesNode = Weaknesses
  xpath <- XML::xpathApply(weaknessesNode, "//Weakness", XML::xmlAttrs)
  dataFrame <- do.call(rbind.data.frame, xpath)
  names(dataFrame) <- c("ID", "Name", "Weakness_Abstraction", "Status")

  xpath2 <- XML::xpathApply(weaknessesNode, "//Weakness/Description")
  dataFrame2 <- XML::xmlToDataFrame(xpath2)

  dataFrame3 <- data.frame(dataFrame, dataFrame2)

  #Getting CVEs associated (one column data frame with CVEs Associated)
  xpath3 <- XML::xpathApply(weaknessesNode, "//Weakness")
  dataFrame4 <- as.data.frame(XML::xmlToDataFrame(xpath3)$Observed_Examples)
  names(dataFrame4) <- c("Associated_CVEs")
  dataFrame4$Associated_CVEs <- as.character(dataFrame4$Associated_CVEs)

  for (i in 1:nrow(dataFrame4)) {
    row <- dataFrame4[i,1]
    # do stuff with row
    dataFrame4[i,1] <- jsonlite::toJSON(getCVElistFromText(row))
  }
  dataFrame5 <- data.frame(dataFrame3, dataFrame4, stringsAsFactors = FALSE)
  dataFrame5$ID <- as.character(dataFrame5$ID)
  dataFrame5$Name <- as.character(dataFrame5$Name)

  return(dataFrame5)
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
  cweDF <- parseCWEtoDF()
  cweDF <- subset(cweDF, ID == id)
  res <- as.character(cweDF$Name)
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
#'
#' @examples getCVElistFromText(CVE-2009-1936chain: library CVE-2005-3335)
getCVElistFromText <- function(string) {
  if (is.na(string)) return("NULL")
  return(regmatches(string, gregexpr("[A-Z]{3}-[0-9]{4}-[0-9]{3,10}", string)))
}



