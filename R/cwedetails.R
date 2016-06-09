# ================
# Public Functions
# ================
library(XML)
library(gtools) #rbind.data.frame(xpath1[[1]], xpath1[[2]], ...) --- do.call(rbind.data.frame, xpath1)
parseXMLtoDF <- function(xml) {
  df <- xmlTreeParse("/Users/barri/Desktop/Universidad/Master/3. Data Driven Security/Rproject/net-security/data/cwec_v2.9.xml", useInternalNodes = TRUE)
  rootNode <- xmlRoot(df) #xmlName(rootNode) = Weakness_Catalog
  weaknessesNode <- rootNode[[3]] #weaknessesNode = Weaknesses
  xpath1 <- xpathApply(weaknessesNode, "//Weakness[@ID='102']", xmlAttrs)
  xpath2 <- xpathApply(weaknessesNode, "//Weakness[@ID='102']") 
  
}

# =================
# Private Functions
# =================
