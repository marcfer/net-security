# ================
# Public Functions
# ================
library(XML)
#library(gtools) #rbind.data.frame(xpath1[[1]], xpath1[[2]], ...) --- do.call(rbind.data.frame, xpath1)
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
  names(dataFrame4) <- c("Associated CVEs")
  
  
}

# =================
# Private Functions
# =================
