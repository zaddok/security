package security

var FuzzyNameMatch [][]string = [][]string{
	{"aaron", "erin", "ronnie", "ron"},
	{"abe", "abraham", "abram"},
	{"abednego", "bedney"},
	{"abel", "ebbie", "ab", "abe", "eb"},
	{"abiel", "ab"},
	{"abigail", "abby", "abbie", "abie"},
	{"abigail", "abbie", "abby", "abie", "abbey", "abbi", "abi", "gail", "gayle"},
	{"abijah", "ab", "bige"},
	{"abner", "ab"},
	{"abraham", "ab", "abe"},
	{"abram", "ab"},
	{"absalom", "app", "ab", "abbie"},
	{"ada", "addy"},
	{"adaline", "delia", "lena", "dell", "addy", "ada"},
	{"adam", "edie", "ade"},
	{"addy", "adele"},
	{"adela", "della"},
	{"adelaide", "heidi", "adele", "dell", "addy", "della"},
	{"adelbert", "del", "albert", "delbert", "bert"},
	{"adele", "dell"},
	{"adeline", "delia", "lena", "dell", "addy", "ada"},
	{"adelphia", "philly", "delphia", "adele", "dell", "addy"},
	{"adolphus", "dolph", "ado", "adolph"},
	{"adrian", "rian"},
	{"adrienne", "adrian"},
	{"agatha", "aggy"},
	{"agnes", "inez", "aggy", "nessa"},
	{"aileen", "lena", "allie"},
	{"alan", "al"},
	{"alanson", "al", "lanson"},
	{"alastair", "al"},
	{"alazama", "ali"},
	{"albert", "al", "bert", "alex"},
	{"alberta", "bert", "allie", "bertie"},
	{"aldo", "al"},
	{"aldrich", "riche", "rich"},
	{"aleva", "levy", "leve"},
	{"alex", "alexandra", "alexander"},
	{"alexander", "al", "alex", "xander", "sandy", "alec", "alek"},
	{"alexandra", "alex", "sandy", "alla", "sandra"},
	{"alexandria", "drina", "alexander", "alla", "sandra"},
	{"alexis", "lexi"},
	{"alfonse", "al"},
	{"alfred", "fred", "freddy", "al", "alf", "alfie"},
	{"alfreda", "freddy", "alfy", "freda", "frieda"},
	{"algernon", "algy"},
	{"alice", "lisa", "elsie", "allie"},
	{"alicia", "lisa", "elsie", "allie"},
	{"aline", "adeline"},
	{"alison", "ali", "ally", "allie"},
	{"alison", "ali"},
	{"allan", "al", "allen"},
	{"allen", "al", "allan"},
	{"allisandra", "allie"},
	{"almena", "mena", "allie"},
	{"almina", "minnie"},
	{"almira", "myra"},
	{"alonzo", "lon", "al", "lonzo"},
	{"alphinias", "alphus"},
	{"alverta", "virdie", "vert"},
	{"alyssa", "lissia", "al", "ally"},
	{"alzada", "zada"},
	{"amanda", "mandy", "manda"},
	{"amanda", "mandy", "mindy"},
	{"ambrose", "brose"},
	{"amelia", "amy", "mel", "millie", "emily"},
	{"amos", "moses"},
	{"amy", "aimee"},
	{"anastasia", "ana", "stacy"},
	{"anderson", "andy"},
	{"andrea", "drea", "rea", "andrew"},
	{"andrew", "andy", "drew"},
	{"angela", "angelica", "angelina", "angel", "angeline", "jane", "angie"},
	{"angelina", "lina"},
	{"ann", "nana", "nan", "nancy", "annie", "nanny"},
	{"anna", "anne", "ann", "annie"},
	{"anne", "annie", "nana", "ann", "nan", "nanny", "nancy"},
	{"annette", "anna", "nettie"},
	{"annie", "ann", "anna"},
	{"anselm", "ansel", "selma", "anse", "ance"},
	{"anthony", "tony"},
	{"antoinette", "tony", "netta", "ann"},
	{"antonia", "tony", "netta", "ann"},
	{"appoline", "appy", "appie"},
	{"aquilla", "quil", "quillie"},
	{"ara", "belle", "arry"},
	{"arabella", "ara", "bella", "arry", "belle"},
	{"araminta", "armida", "middie", "ruminta", "minty"},
	{"archibald", "archie"},
	{"archilles", "kill", "killis"},
	{"ariadne", "arie"},
	{"arielle", "arie"},
	{"aristotle", "telly"},
	{"arizona", "onie", "ona"},
	{"arlene", "arly", "lena"},
	{"armanda", "mandy"},
	{"armena", "mena", "arry"},
	{"armilda", "milly"},
	{"arminda", "mindie"},
	{"arminta", "minite", "minnie"},
	{"arnold", "arnie"},
	{"art", "arthur"},
	{"artelepsa", "epsey"},
	{"artemus", "art"},
	{"arthur", "art"},
	{"arthusa", "thursa"},
	{"arzada", "zaddi"},
	{"asahel", "asa"},
	{"asaph", "asa"},
	{"asenath", "sene", "assene", "natty"},
	{"aubrey", "bree"},
	{"audrey", "dee"},
	{"august", "gus"},
	{"augusta", "tina", "aggy", "gatsy", "gussie"},
	{"augustina", "tina", "aggy", "gatsy", "gussie"},
	{"augustine", "gus", "austin", "august"},
	{"augustus", "gus", "austin", "august"},
	{"aurelia", "ree", "rilly", "orilla", "aurilla", "ora"},
	{"avarilla", "rilla"},
	{"azariah", "riah", "aze"},
	{"bab", "barby"},
	{"babs", "barby", "barbara", "bab"},
	{"barbara", "barb", "barbie"},
	{"barbara", "barby", "babs", "bab", "bobbie"},
	{"barbery", "barbara"},
	{"barbie", "barbara"},
	{"barnabas", "barney"},
	{"barney", "barnabas"},
	{"bart", "bartholomew"},
	{"bartholomew", "bartel", "bat", "meus", "bart", "mees"},
	{"barticus", "bart"},
	{"bazaleel", "basil"},
	{"bea", "beatrice"},
	{"beatrice", "bea", "trisha", "trixie", "trix"},
	{"becca", "beck"},
	{"beck", "becky"},
	{"bedelia", "delia", "bridgit"},
	{"belinda", "belle", "linda"},
	{"bella", "belle", "arabella", "isabella"},
	{"ben", "benjamin", "bennie"},
	{"benedict", "bennie", "ben"},
	{"benjamin", "benjy", "jamie", "benny", "bennie", "ben"},
	{"benjy", "benjamin"},
	{"bernard", "barney", "bernie", "berney"},
	{"berney", "bernie"},
	{"bert", "bertie", "bob", "bobby"},
	{"bertha", "bert", "birdie", "bertie"},
	{"bertram", "bert"},
	{"bess", "bessie"},
	{"beth", "betsy", "betty", "elizabeth", "bethany"},
	{"bethena", "beth", "thaney"},
	{"beverly", "beverley", "bev"},
	{"bezaleel", "zeely"},
	{"biddie", "biddy"},
	{"bill", "william", "billy", "robert", "willie", "fred"},
	{"blanche", "bea"},
	{"boetius", "bo"},
	{"brad", "bradford", "ford"},
	{"bradford", "ford", "brad"},
	{"bradley", "brad"},
	{"brady", "brody"},
	{"brenda", "brandy"},
	{"brian", "bryan", "bryant"},
	{"bridget", "bridie", "biddy", "bridgie", "biddie"},
	{"brittany", "britt"},
	{"broderick", "ricky", "brody", "brady", "rick"},
	{"caldonia", "calliedona"},
	{"caleb", "cal"},
	{"california", "callie"},
	{"calista", "kissy"},
	{"calpurnia", "cally"},
	{"calvin", "cal", "vin", "vinny"},
	{"cameron", "ron", "cam", "ronny"},
	{"camille", "millie", "cammie"},
	{"campbell", "cam"},
	{"candace", "candy", "dacey"},
	{"carlotta", "lottie"},
	{"carlton", "carl"},
	{"carmellia", "mellia"},
	{"carmon", "charm", "cammie", "carm"},
	{"carol", "lynn", "carrie", "carolann", "cassie", "caroline", "carole"},
	{"carolann", "carol", "carole"},
	{"caroline", "lynn", "carol", "carrie", "cassie", "carole"},
	{"carolyn", "lynn", "carrie", "cassie"},
	{"carthaette", "etta", "etty"},
	{"casper", "jasper"},
	{"cassandra", "sandy", "cassie", "sandra"},
	{"cassie", "cassandra"},
	{"caswell", "cass"},
	{"catherine", "kathy", "katy", "lena", "kittie", "kit", "trina", "cathy", "kay", "cassie"},
	{"cathleen", "kathy", "katy", "lena", "kittie", "kit", "trina", "cathy", "kay", "cassie"},
	{"cathy", "kathy", "cathleen", "catherine"},
	{"cecilia", "cissy", "celia"},
	{"cedric", "ced", "rick", "ricky"},
	{"celeste", "lessie", "celia"},
	{"celinda", "linda", "lynn", "lindy"},
	{"charity", "chat"},
	{"charlene", "char"},
	{"charles", "charlie", "charley", "chuck", "carl", "chick"},
	{"charlie", "charles", "chuck"},
	{"charlotte", "char", "sherry", "lotte", "lottie", "lotta", "charlie"},
	{"chauncey", "chan"},
	{"cher", "sher"},
	{"cheryl", "sheryl"},
	{"chesley", "chet"},
	{"chester", "chet"},
	{"chet", "chester"},
	{"chick", "charlotte", "caroline", "chuck"},
	{"chloe", "clo"},
	{"chris", "christina", "christopher", "christine"},
	{"christa", "chris"},
	{"christian", "chris", "kit"},
	{"christiana", "kris", "kristy", "ann", "tina", "christy", "chris", "crissy"},
	{"christina", "kris", "kristy", "tina", "christy", "chris", "crissy"},
	{"christine", "kris", "kristy", "chrissy", "tina", "chris", "crissy"},
	{"christopher", "chris", "kit"},
	{"christy", "crissy"},
	{"cicely", "cilla"},
	{"cinderella", "arilla", "rella", "cindy", "rilla"},
	{"cinderlla", "cindy"},
	{"claire", "clair", "clare", "clara"},
	{"clara", "clarissa"},
	{"clare", "clara"},
	{"clarence", "clare", "clair"},
	{"clarinda", "clara"},
	{"clarissa", "cissy", "clara"},
	{"claudia", "claud"},
	{"cleatus", "cleat"},
	{"clement", "clem"},
	{"clementine", "clement", "clem"},
	{"cliff", "clifford", "cliff"},
	{"clifford", "ford", "cliff"},
	{"clifton", "tony", "cliff"},
	{"cole", "colie"},
	{"columbus", "clum"},
	{"con", "conny"},
	{"conrad", "conny", "con"},
	{"constance", "connie"},
	{"cordelia", "cordy", "delia"},
	{"corey", "coco", "cordy", "ree"},
	{"corinne", "cora", "ora"},
	{"cornelia", "nelly", "cornie", "nelia", "corny", "nelle"},
	{"cornelius", "conny", "niel", "corny", "con"},
	{"cory", "coco", "cordy", "ree"},
	{"courtney", "curt", "court"},
	{"crystal", "chris", "tal", "stal", "crys"},
	{"curtis", "curt"},
	{"cynthia", "cintha", "cindy"},
	{"cyrenius", "swene", "cy", "serene", "renius", "cene"},
	{"cyrus", "cy"},
	{"daisy", "margaret"},
	{"dal", "dahl"},
	{"dalton", "dahl"},
	{"dan", "danny", "daniel"},
	{"daniel", "dan", "danny"},
	{"danielle", "ellie", "dani"},
	{"danny", "daniel"},
	{"daphne", "daph", "daphie"},
	{"darlene", "lena", "darry"},
	{"david", "dave", "davey", "day"},
	{"deanne", "ann", "dee"},
	{"deb", "deborah", "debra"},
	{"debbie", "deb", "debra", "deborah", "debby"},
	{"debby", "deb"},
	{"debora", "deb", "debbie", "debby"},
	{"deborah", "deb", "debbie", "debby"},
	{"debra", "deb", "debbie"},
	{"deidre", "deedee"},
	{"delbert", "bert", "del"},
	{"delia", "fidelia", "cordelia", "delius"},
	{"delilah", "lil", "lila", "dell", "della"},
	{"deliverance", "delly", "dilly", "della"},
	{"dell", "della"},
	{"della", "adela", "delilah", "adelaide"},
	{"delores", "lolly", "lola", "della", "dee", "dell"},
	{"delpha", "philadelphia"},
	{"delphine", "delphi", "del", "delf"},
	{"demaris", "dea", "maris", "mary"},
	{"demerias", "dea", "maris", "mary"},
	{"democrates", "mock"},
	{"denise", "dennis"},
	{"dennis", "denny"},
	{"dennison", "denny"},
	{"derrick", "ricky", "eric", "rick"},
	{"deuteronomy", "duty"},
	{"diana", "dicey", "didi", "di"},
	{"diane", "dicey", "didi", "di"},
	{"dicey", "dicie"},
	{"dick", "rick", "richard"},
	{"dickson", "dick"},
	{"domenic", "dom"},
	{"dominic", "dom"},
	{"don", "donald"},
	{"donald", "dony", "donnie", "don", "donny"},
	{"donnie", "donald", "donny"},
	{"donny", "donald"},
	{"dorcus", "darkey"},
	{"dorinda", "dorothea", "dora"},
	{"doris", "dora"},
	{"dorothea", "doda", "dora"},
	{"dorothy", "dortha", "dolly", "dot", "dotty"},
	{"dorothy", "dot", "dotty"},
	{"dot", "dotty"},
	{"dotha", "dotty"},
	{"douglas", "doug"},
	{"drew", "andrew"},
	{"drusilla", "silla"},
	{"duncan", "dunc"},
	{"duncan", "dunk"},
	{"earnest", "ernestine", "ernie"},
	{"eb", "ebbie"},
	{"ebenezer", "ebbie", "eben", "eb"},
	{"ed", "eddie", "eddy"},
	{"eddie", "eddy"},
	{"edgar", "ed", "eddie", "eddy"},
	{"edith", "edie", "edye"},
	{"edmond", "ed", "eddie", "eddy"},
	{"edmund", "ed", "eddie", "ted", "eddy", "ned"},
	{"edna", "edny"},
	{"eduardo", "ed", "eddie", "eddy"},
	{"edward", "ned", "ed", "eddy", "eddie"},
	{"edward", "teddy", "ed", "ned", "ted", "eddy", "eddie"},
	{"edwin", "ed", "eddie", "win", "eddy", "ned"},
	{"edwina", "edwin"},
	{"edyth", "edie", "edye"},
	{"edythe", "edie", "edye"},
	{"egbert", "bert", "burt"},
	{"eighta", "athy"},
	{"eileen", "helen"},
	{"elaine", "lainie", "helen"},
	{"elbert", "albert"},
	{"elbertson", "elbert", "bert"},
	{"eleanor", "lanna", "nora", "nelly", "ellie", "elaine", "ellen", "lenora"},
	{"eleazer", "lazar"},
	{"elena", "helen"},
	{"elias", "eli", "lee", "lias"},
	{"elijah", "lige", "eli"},
	{"eliphalel", "life"},
	{"eliphalet", "left"},
	{"elisa", "lisa"},
	{"elisha", "lish", "eli"},
	{"eliza", "elizabeth"},
	{"elizabeth", "libby", "lisa", "lib", "lizzie", "eliza", "betsy", "liza", "betty", "bessie", "bess", "beth", "liz"},
	{"elizabeth", "liz", "lizzie", "liza", "libb", "lisbeth", "beth", "bessie", "bess"},
	{"ella", "ellen"},
	{"ellen", "nellie", "nell", "helen"},
	{"ellender", "nellie", "ellen", "helen"},
	{"ellie", "elly"},
	{"ellswood", "elsey"},
	{"elminie", "minnie"},
	{"elmira", "ellie", "elly", "mira"},
	{"elnora", "nora"},
	{"eloise", "heloise", "louise"},
	{"elouise", "louise"},
	{"elsie", "elsey"},
	{"elswood", "elsey"},
	{"elvira", "elvie"},
	{"elwood", "woody"},
	{"elysia", "lisa"},
	{"elze", "elsey"},
	{"emanuel", "manuel", "manny"},
	{"emeline", "em", "emmy", "emma", "milly", "emily"},
	{"emil", "emily"},
	{"emily", "em", "emy"},
	{"emily", "emmy", "millie", "emma", "mel"},
	{"emma", "emmy"},
	{"epaphroditius", "dite", "ditus", "eppa", "dyche", "dyce"},
	{"ephraim", "eph"},
	{"erasmus", "raze", "rasmus"},
	{"eric", "rick", "ricky"},
	{"ernest", "ernie"},
	{"ernestine", "teeny", "ernest", "tina", "erna"},
	{"erwin", "irwin"},
	{"eseneth", "senie"},
	{"essy", "es"},
	{"estella", "essy", "stella"},
	{"estelle", "essy", "stella"},
	{"esther", "hester", "essie"},
	{"eudicy", "dicey"},
	{"eudora", "dora"},
	{"eudoris", "dossie", "dosie"},
	{"eugene", "gene"},
	{"eunice", "nicie"},
	{"euphemia", "effie", "effy"},
	{"eurydice", "dicey"},
	{"eustacia", "stacia", "stacy"},
	{"eva", "eve"},
	{"evaline", "eva", "lena", "eve"},
	{"evangeline", "ev", "evan", "vangie"},
	{"evelyn", "evelina", "ev", "eve"},
	{"experience", "exie"},
	{"ezekiel", "zeke", "ez"},
	{"ezideen", "ez"},
	{"ezra", "ez"},
	{"faith", "fay"},
	{"felicia", "fel", "felix", "feli"},
	{"felicity", "flick", "tick"},
	{"feltie", "felty"},
	{"ferdinand", "freddie", "freddy", "ferdie", "fred"},
	{"ferdinando", "nando", "ferdie", "fred"},
	{"fidelia", "delia"},
	{"flo", "florence"},
	{"flora", "florence"},
	{"florence", "flossy", "flora", "flo"},
	{"floyd", "lloyd"},
	{"fran", "frannie"},
	{"frances", "sis", "cissy", "frankie", "franniey", "fran", "francie", "frannie", "fanny"},
	{"francie", "francine"},
	{"francine", "franniey", "fran", "frannie", "francie"},
	{"francis", "fran", "frankie", "frank"},
	{"frank", "franklin"},
	{"frankie", "frank", "francis"},
	{"franklin", "fran", "frank"},
	{"franklind", "frank"},
	{"fred", "freddy", "frederick"},
	{"freda", "frieda"},
	{"frederica", "frederick"},
	{"frederick", "freddie", "freddy", "fritz", "fred"},
	{"fredericka", "freddy", "ricka", "freda", "frieda"},
	{"frieda", "freddie", "freddy", "fred"},
	{"gabby", "gabriella", "gabe", "gabrielle"},
	{"gabe", "gabriel"},
	{"gabriel", "gabe", "gabie", "gabby"},
	{"gabriella", "ella", "gabby"},
	{"gabrielle", "ella", "gabby"},
	{"genevieve", "jean", "eve", "jenny"},
	{"geoff", "geoffrey", "jeffrey", "jeff"},
	{"geoffrey", "geoff", "jeff"},
	{"george", "jorge", "georgiana"},
	{"georgia", "george", "georgiana"},
	{"gerald", "gerry", "jerry"},
	{"geraldine", "gerry", "gerrie", "jerry", "dina"},
	{"gerhardt", "gay"},
	{"gerrie", "geraldine"},
	{"gerry", "gerald", "geraldine", "jerry"},
	{"gert", "gertie"},
	{"gertie", "gertrude"},
	{"gertrude", "gertie", "gert", "trudy"},
	{"gil", "gilbert"},
	{"gilbert", "bert", "gil", "wilber"},
	{"gloria", "glory"},
	{"governor", "govie"},
	{"greenberry", "green", "berry"},
	{"gregory", "greg"},
	{"gretchen", "margaret"},
	{"griselda", "grissel"},
	{"gum", "monty"},
	{"gus", "gussie"},
	{"gustavus", "gus"},
	{"gwen", "gwendolyn", "wendy"},
	{"gwendolyn", "gwen", "wendy"},
	{"hamilton", "ham"},
	{"hannah", "nan", "nanny", "anna"},
	{"harold", "hal", "harry"},
	{"harriet", "hattie"},
	{"harry", "harold", "henry"},
	{"haseltine", "hassie"},
	{"heather", "hetty"},
	{"helen", "lena", "ella", "ellen", "ellie"},
	{"helena", "eileen", "lena", "nell", "nellie", "eleanor", "elaine", "ellen", "aileen"},
	{"helene", "lena", "ella", "ellen", "ellie"},
	{"heloise", "lois", "eloise", "elouise"},
	{"henrietta", "hank", "etta", "etty", "retta", "nettie"},
	{"henry", "hank", "hal", "harry"},
	{"henry", "harry", "hal"},
	{"hephsibah", "hipsie"},
	{"hepsibah", "hipsie"},
	{"herb", "herbert"},
	{"herbert", "bert", "herb"},
	{"herman", "harman", "dutch"},
	{"hermione", "hermie"},
	{"hester", "hessy", "esther", "hetty"},
	{"hezekiah", "hy", "hez", "kiah"},
	{"hilary", "hil"},
	{"hiram", "hy"},
	{"honora", "honey", "nora", "norry", "norah"},
	{"hopkins", "hopp", "hop"},
	{"horace", "horry"},
	{"hortense", "harty", "tensey"},
	{"hosea", "hosey", "hosie"},
	{"howard", "hal", "howie"},
	{"hubert", "bert", "hugh", "hub"},
	{"ian", "john"},
	{"ignatius", "natius", "iggy", "nate", "nace"},
	{"ignatzio", "naz", "iggy", "nace"},
	{"immanuel", "manuel", "emmanuel"},
	{"india", "indie", "indy"},
	{"inez", "agnes"},
	{"iona", "onnie"},
	{"irene", "rena"},
	{"irvin", "irving"},
	{"irving", "irv"},
	{"irwin", "erwin"},
	{"isaac", "ike", "zeke", "isaak"},
	{"isabel", "tibbie", "bell", "nib", "belle", "bella", "nibby", "ib", "issy"},
	{"isabella", "tibbie", "nib", "belle", "bella", "nibby", "ib", "issy"},
	{"isabelle", "tibbie", "nib", "belle", "bella", "nibby", "ib", "issy"},
	{"isadora", "issy", "dora"},
	{"isaiah", "zadie", "zay"},
	{"isidore", "izzy"},
	{"iva", "ivy"},
	{"ivan", "john"},
	{"jackson", "jack"},
	{"jacob", "jaap", "jake", "jay"},
	{"jacob", "jake"},
	{"jacobus", "jacob"},
	{"jacqueline", "jackie", "jack"},
	{"jahoda", "hody", "hodie", "hoda"},
	{"james", "jamie", "jim", "jimmy", "jimbo"},
	{"james", "jimmy", "jim", "jamie", "jimmie", "jem"},
	{"jamie", "james"},
	{"jane", "janie", "jessie", "jean", "jennie"},
	{"janet", "jan", "jessie"},
	{"janice", "jan"},
	{"jannett", "nettie"},
	{"jasper", "jap", "casper"},
	{"jayme", "jay"},
	{"jean", "jane", "jeannie"},
	{"jeanette", "jessie", "jean", "janet", "nettie"},
	{"jeanne", "jane", "jeannie"},
	{"jeb", "jebadiah"},
	{"jedediah", "dyer", "jed", "diah"},
	{"jedidiah", "jed"},
	{"jeff", "geoffrey", "jeffrey"},
	{"jefferey", "jeff"},
	{"jefferson", "sonny", "jeff"},
	{"jeffrey", "geoff", "jeff"},
	{"jehiel", "hiel"},
	{"jehu", "hugh", "gee"},
	{"jemima", "mima"},
	{"jennet", "jessie", "jenny"},
	{"jennifer", "jennie"},
	{"jennifer", "jenny", "jen"},
	{"jenny", "jennifer"},
	{"jeremiah", "jereme", "jerry"},
	{"jerita", "rita"},
	{"jerry", "jereme", "geraldine"},
	{"jessica", "jessie"},
	{"jessie", "jane", "jess", "janet"},
	{"jim", "jimmie"},
	{"jincy", "jane"},
	{"jinsy", "jane"},
	{"joan", "jo", "nonie"},
	{"joann", "jo"},
	{"joanna", "hannah", "jody", "jo", "joan"},
	{"joanne", "jo"},
	{"jody", "jo"},
	{"joe", "joseph", "joey"},
	{"joey", "joseph"},
	{"johanna", "jo"},
	{"johannah", "hannah", "jody", "joan", "nonie"},
	{"johannes", "jonathan", "john", "johnny"},
	{"john", "jack", "johnny", "jock"},
	{"john", "johnny", "jack", "jake"},
	{"jon", "john", "nathan"},
	{"jonathan", "john", "nathan"},
	{"jonathan", "jon", "john", "jono", "jonno"},
	{"joseph", "jody", "jos", "joe", "joey"},
	{"joseph", "joe", "joey"},
	{"josephine", "fina", "jody", "jo", "josey", "joey"},
	{"josetta", "jettie"},
	{"josey", "josophine"},
	{"josh", "joshua"},
	{"joshua", "jos", "josh"},
	{"joshua", "josh"},
	{"josiah", "jos"},
	{"joyce", "joy"},
	{"juanita", "nita", "nettie"},
	{"judah", "juder", "jude"},
	{"judith", "judie", "juda", "judy", "judi", "jude"},
	{"judson", "sonny", "jud"},
	{"judy", "judith"},
	{"julia", "julie", "jill"},
	{"julian", "jule"},
	{"julias", "jule"},
	{"julie", "julia", "jule"},
	{"june", "junius"},
	{"junior", "junie", "june", "jr"},
	{"justin", "justus", "justina"},
	{"karonhappuck", "karon", "karen", "carrie", "happy"},
	{"kasey", "k.c."},
	{"katarina", "catherine", "tina"},
	{"kate", "kay"},
	{"katelin", "kay", "kate", "kaye"},
	{"katelyn", "kay", "kate", "kaye"},
	{"katherine", "kathy", "katy", "lena", "kittie", "kaye", "kit", "trina", "cathy", "kay", "kate", "cassie"},
	{"kathleen", "kathy", "katy", "lena", "kittie", "kit", "trina", "cathy", "kay", "cassie"},
	{"kathryn", "kate", "katie"},
	{"kathryn", "kathy"},
	{"katy", "kathy"},
	{"kayla", "kay"},
	{"ken", "kenneth"},
	{"kendall", "ken", "kenny"},
	{"kendra", "kenj", "kenji", "kay", "kenny"},
	{"kendrick", "ken", "kenny"},
	{"kenneth", "ken", "kenny", "kendrick"},
	{"kenny", "ken", "kenneth"},
	{"kent", "ken", "kenny", "kendrick"},
	{"keziah", "kizza", "kizzie"},
	{"kim", "kimberly", "kimberley"},
	{"kimberley", "kim"},
	{"kimberly", "kim"},
	{"kingsley", "king"},
	{"kingston", "king"},
	{"kit", "kittie"},
	{"kris", "chris"},
	{"kristel", "kris"},
	{"kristen", "chris"},
	{"kristin", "chris"},
	{"kristine", "kris", "kristy", "tina", "christy", "chris", "crissy"},
	{"kristopher", "chris", "kris"},
	{"kristy", "chris"},
	{"lafayette", "laffie", "fate"},
	{"lamont", "monty"},
	{"laodicia", "dicy", "cenia"},
	{"larry", "laurence", "lawrence"},
	{"lauren", "ren", "laurie"},
	{"laurence", "lorry", "larry", "lon", "lonny", "lorne"},
	{"laurinda", "laura", "lawrence"},
	{"lauryn", "laurie"},
	{"laveda", "veda"},
	{"laverne", "vernon", "verna"},
	{"lavina", "vina", "viney", "ina"},
	{"lavinia", "vina", "viney", "ina"},
	{"lavonia", "vina", "vonnie", "wyncha", "viney"},
	{"lavonne", "von"},
	{"lawrence", "larry", "laurie"},
	{"lawrence", "lorry", "larry", "lon", "lonny", "lorne"},
	{"leanne", "lea", "annie"},
	{"lecurgus", "curg"},
	{"lemuel", "lem"},
	{"lena", "ellen"},
	{"lenora", "nora", "lee"},
	{"leo", "leon"},
	{"leonard", "lineau", "leo", "leon", "len", "lenny"},
	{"leonidas", "lee", "leon"},
	{"leonora", "nora", "nell", "nellie"},
	{"leonore", "nora", "honor", "elenor"},
	{"leroy", "roy", "lee", "l.r."},
	{"les", "lester"},
	{"leslie", "les"},
	{"lester", "les"},
	{"letitia", "tish", "titia", "lettice", "lettie"},
	{"levi", "lee"},
	{"levicy", "vicy"},
	{"levone", "von"},
	{"lib", "libby"},
	{"lidia", "lyddy"},
	{"lil", "lilly", "lily"},
	{"lillah", "lil", "lilly", "lily", "lolly"},
	{"lillian", "lil", "lilly", "lolly"},
	{"lilly", "lily"},
	{"lincoln", "link"},
	{"linda", "lindy", "lynn"},
	{"lindy", "lynn"},
	{"lionel", "leon"},
	{"lisa", "lizzie", "alice", "liz", "melissa"},
	{"littleberry", "little", "berry", "l.b."},
	{"liz", "elizabeth"},
	{"lizzie", "elizabeth", "liz"},
	{"lois", "lou", "louise"},
	{"lon", "lonzo"},
	{"lorenzo", "loren"},
	{"loretta", "etta", "lorrie", "retta"},
	{"lorraine", "lorrie"},
	{"lotta", "lottie"},
	{"lou", "louis", "lu"},
	{"louis", "lewis", "louise", "louie", "lou"},
	{"louisa", "eliza", "lou", "lois"},
	{"louise", "eliza", "lou", "lois"},
	{"louvinia", "vina", "vonnie", "wyncha", "viney"},
	{"lucas", "luke"},
	{"lucia", "lucy", "lucius"},
	{"lucias", "luke"},
	{"lucille", "cille", "lu", "lucy", "lou"},
	{"lucina", "sinah"},
	{"lucinda", "lu", "lucy", "cindy", "lou"},
	{"lucretia", "creasey"},
	{"lucy", "lucinda"},
	{"luella", "lula", "ella", "lu"},
	{"luke", "lucas"},
	{"lunetta", "nettie"},
	{"lurana", "lura"},
	{"luther", "luke"},
	{"lydia", "lyddy"},
	{"lyndon", "lindy", "lynn"},
	{"mabel", "mehitabel", "amabel"},
	{"mac", "mc"},
	{"mack", "mac", "mc"},
	{"mackenzie", "kenzy", "mac", "mack"},
	{"maddy", "madelyn", "madeline", "madge"},
	{"madeline", "maggie", "lena", "magda", "maddy", "madge", "maddi", "madie", "maddie"},
	{"madie", "madeline", "madelyn"},
	{"madison", "mattie", "maddy"},
	{"magdalena", "maggie", "lena"},
	{"magdelina", "lena", "magda", "madge"},
	{"mahala", "hallie"},
	{"malachi", "mally"},
	{"malcolm", "mac", "mal", "malc"},
	{"malinda", "lindy"},
	{"manda", "mandy"},
	{"mandy", "amanda"},
	{"manerva", "minerva", "nervie", "eve", "nerva"},
	{"manny", "manuel"},
	{"manoah", "noah"},
	{"manola", "nonnie"},
	{"manuel", "emanuel", "manny"},
	{"marcus", "mark"},
	{"margaret", "maggie", "meg", "maisie"},
	{"margaret", "maggie", "meg", "peg", "midge", "margy", "margie", "madge", "peggy", "maggy", "marge", "daisy", "margery", "gretta", "rita"},
	{"margaretta", "maggie", "meg", "peg", "midge", "margie", "madge", "peggy", "marge", "daisy", "margery", "gretta", "rita"},
	{"margarita", "maggie", "meg", "metta", "midge", "greta", "megan", "maisie", "madge", "marge", "daisy", "peggie", "rita", "margo"},
	{"marge", "margery", "margaret", "margaretta"},
	{"margie", "marjorie", "margie"},
	{"marguerite", "peggy"},
	{"margy", "marjorie"},
	{"mariah", "mary", "maria"},
	{"marian", "marianna", "marion"},
	{"marie", "mae"},
	{"marietta", "mariah", "mercy", "polly", "may", "molly", "mitzi", "minnie", "mollie", "mae", "maureen", "marion", "marie", "mamie", "mary", "maria"},
	{"marilyn", "mary"},
	{"marion", "mary"},
	{"marissa", "rissa"},
	{"marjorie", "margy", "margie"},
	{"marsha", "marcie", "mary"},
	{"martha", "marty", "mattie", "mat", "patsy", "patty"},
	{"martin", "marty"},
	{"martina", "tina"},
	{"martine", "tine"},
	{"marv", "marvin"},
	{"marvin", "marv"},
	{"mary", "mamie", "molly", "mae", "polly", "mitzi"},
	{"mat", "mattie"},
	{"mathilda", "tillie", "patty"},
	{"matilda", "tilly", "maud", "matty"},
	{"matt", "mathew", "matthew"},
	{"matthew", "thys", "matt", "thias", "mattie", "matty"},
	{"matthias", "thys", "matt", "thias"},
	{"maud", "middy"},
	{"maureen", "mary"},
	{"maurice", "morey"},
	{"mavery", "mave"},
	{"mavine", "mave"},
	{"maxine", "max"},
	{"may", "mae"},
	{"mckenna", "ken", "kenna", "meaka"},
	{"medora", "dora"},
	{"megan", "meg"},
	{"mehitabel", "hetty", "mitty", "mabel", "hitty"},
	{"melanie", "mellie"},
	{"melchizedek", "zadock", "dick"},
	{"melinda", "linda", "mel", "lynn", "mindy", "lindy"},
	{"melissa", "lisa", "mel", "missy", "milly", "lissa"},
	{"mellony", "mellia"},
	{"melody", "lodi"},
	{"melvin", "mel"},
	{"melvina", "vina"},
	{"mercedes", "merci", "sadie", "mercy"},
	{"merv", "mervin"},
	{"mervyn", "merv"},
	{"micajah", "cage"},
	{"michael", "micky", "mike", "micah", "mick"},
	{"michael", "mike", "mick", "micky"},
	{"michelle", "mickey"},
	{"mick", "micky"},
	{"mike", "micky", "mick", "michael"},
	{"mildred", "milly"},
	{"millicent", "missy", "milly"},
	{"minerva", "minnie"},
	{"minnie", "wilhelmina"},
	{"miranda", "randy", "mandy", "mira"},
	{"miriam", "mimi", "mitzi", "mitzie"},
	{"missy", "melissa"},
	{"mitch", "mitchell"},
	{"mitchell", "mitch"},
	{"mitzi", "mary", "mittie", "mitty"},
	{"mitzie", "mittie", "mitty"},
	{"monet", "nettie"},
	{"monica", "monna", "monnie"},
	{"monteleon", "monte"},
	{"montesque", "monty"},
	{"montgomery", "monty", "gum"},
	{"monty", "lamont"},
	{"morris", "morey"},
	{"mortimer", "mort"},
	{"moses", "amos", "mose", "moss"},
	{"muriel", "mur"},
	{"myrtle", "myrt", "myrti", "mert"},
	{"nadine", "nada", "deedee"},
	{"nancy", "ann", "nan", "nanny"},
	{"naomi", "omi"},
	{"napoleon", "nap", "nappy", "leon"},
	{"natalie", "natty", "nettie"},
	{"natasha", "tash", "tasha"},
	{"natasha", "tasha", "nat"},
	{"nathan", "nate", "nat"},
	{"nathaniel", "than", "nathan", "nate", "nat", "natty"},
	{"nelle", "nelly"},
	{"nelson", "nels"},
	{"newt", "newton"},
	{"nicholas", "nick", "claes", "claas"},
	{"nicholas", "nick", "nicky"},
	{"nick", "nik", "nicholas"},
	{"nickie", "nicholas"},
	{"nicodemus", "nick"},
	{"nicola", "nicky"},
	{"nicole", "nole", "nikki", "cole"},
	{"nik", "nick"},
	{"nora", "nonie"},
	{"norbert", "bert", "norby"},
	{"nowell", "noel"},
	{"obadiah", "dyer", "obed", "obie", "diah"},
	{"obedience", "obed", "beda", "beedy", "biddie"},
	{"obie", "obediah"},
	{"octavia", "tave", "tavia"},
	{"odell", "odo"},
	{"olive", "nollie", "livia", "ollie"},
	{"oliver", "ollie"},
	{"olivia", "nollie", "livia", "ollie"},
	{"ollie", "oliver"},
	{"onicyphorous", "cyphorus", "osaforus", "syphorous", "one", "cy", "osaforum"},
	{"orilla", "rilly", "ora"},
	{"orlando", "roland"},
	{"orphelia", "phelia"},
	{"ossy", "ozzy"},
	{"oswald", "ozzy", "waldo", "ossy"},
	{"otis", "ode", "ote"},
	{"ozzy", "oswald"},
	{"pamela", "pam", "pammy"},
	{"pamela", "pam"},
	{"pandora", "dora"},
	{"parmelia", "amelia", "milly", "melia"},
	{"parthenia", "teeny", "parsuny", "pasoonie", "phenie"},
	{"pat", "patrick", "pat", "patricia"},
	{"patience", "pat", "patty"},
	{"patricia", "pat", "patty", "patsy", "trish", "trisha"},
	{"patricia", "tricia", "pat", "patsy", "patty"},
	{"patrick", "pate", "peter", "pat", "patsy", "paddy"},
	{"patsy", "patty"},
	{"patty", "patricia"},
	{"paul", "polly", "paula", "pauly", "pauley", "pauline"},
	{"paula", "polly", "lina"},
	{"paulina", "polly", "lina"},
	{"pauline", "polly"},
	{"peg", "peggy"},
	{"pelegrine", "perry"},
	{"penelope", "penny"},
	{"percival", "percy"},
	{"peregrine", "perry"},
	{"permelia", "melly", "milly", "mellie"},
	{"pernetta", "nettie"},
	{"persephone", "seph", "sephy"},
	{"pete", "peter"},
	{"peter", "pete", "pate"},
	{"peter", "pete", "pita"},
	{"petronella", "nellie"},
	{"pheney", "josephine"},
	{"pheriba", "pherbia", "ferbie"},
	{"philadelphia", "delphia"},
	{"philander", "fie"},
	{"philetus", "leet", "phil"},
	{"philinda", "linda", "lynn", "lindy"},
	{"philip", "phil", "phillip", "philip"},
	{"philipina", "phoebe", "penie"},
	{"philippa", "pippa"},
	{"philly", "delphia"},
	{"philomena", "menaalmena"},
	{"phoebe", "fifi"},
	{"pinckney", "pink"},
	{"pleasant", "ples"},
	{"pocahontas", "pokey"},
	{"posthuma", "humey"},
	{"prescott", "scotty", "scott", "pres"},
	{"priscilla", "prissy", "cissy", "cilla"},
	{"providence", "provy"},
	{"prudence", "prue", "prudy"},
	{"prudy", "prudence"},
	{"rachel", "rae", "rach"},
	{"rachel", "shelly"},
	{"rafaela", "rafa"},
	{"ramona", "mona"},
	{"randolph", "dolph", "randy"},
	{"raphael", "ralph"},
	{"ray", "raymond"},
	{"raymond", "ray"},
	{"reba", "beck", "becca"},
	{"rebecca", "beck", "becca", "reba", "becky", "beckie", "bec"},
	{"reg", "reggie"},
	{"reggie", "reginald"},
	{"regina", "reggie", "gina"},
	{"reginald", "reggie", "naldo", "reg", "renny"},
	{"relief", "leafa"},
	{"reuben", "rube"},
	{"reynold", "reginald"},
	{"rhoda", "rodie"},
	{"rhodella", "della"},
	{"rhyna", "rhynie"},
	{"ricardo", "rick", "ricky"},
	{"rich", "dick", "rick", "riche", "richard"},
	{"richard", "dick", "dickon", "dickie", "dicky", "rick", "rich", "ricky"},
	{"richard", "richie", "rick", "dick"},
	{"richie", "richard"},
	{"rick", "ricky"},
	{"ricky", "dick", "rich"},
	{"robert", "bob", "rob", "robert", "bobby", "bobbie"},
	{"robert", "hob", "hobkin", "dob", "rob", "bobby", "dobbin", "bob"},
	{"robert", "rob", "bob", "bobby", "robbie"},
	{"roberta", "robbie", "bert", "bobbie", "birdie", "bertie"},
	{"roderick", "rod", "erick", "rickie"},
	{"rodger", "roge", "bobby", "hodge", "rod", "robby", "rupert", "robin"},
	{"roger", "roge", "bobby", "hodge", "rod", "robby", "rupert", "robin"},
	{"roland", "rollo", "lanny", "orlando", "rolly"},
	{"ronald", "naldo", "ron", "ronny"},
	{"ronald", "ron", "ronnie", "ronny"},
	{"ronnie", "ronald"},
	{"ronny", "ronald"},
	{"rosa", "rose"},
	{"rosabel", "belle", "roz", "rosa", "rose"},
	{"rosabella", "belle", "roz", "rosa", "rose"},
	{"rosalinda", "linda", "roz", "rosa", "rose"},
	{"rosalyn", "linda", "roz", "rosa", "rose"},
	{"roscoe", "ross"},
	{"rose", "rosie"},
	{"roseann", "rose", "ann", "rosie", "roz"},
	{"roseanna", "rose", "ann", "rosie", "roz"},
	{"roseanne", "ann"},
	{"rosina", "sina"},
	{"roxane", "rox", "roxie"},
	{"roxanna", "roxie", "rose", "ann"},
	{"roxanne", "roxie", "rose", "ann"},
	{"roz", "rosalyn"},
	{"rube", "reuben"},
	{"rudolph", "dolph", "rudy", "olph", "rolf"},
	{"rudolphus", "dolph", "rudy", "olph", "rolf"},
	{"rudy", "rudolph"},
	{"russ", "russell"},
	{"russell", "russ", "rusty"},
	{"rusty", "russell"},
	{"ryan", "ry"},
	{"sabrina", "brina"},
	{"sally", "sal"},
	{"salome", "loomie"},
	{"salvador", "sal"},
	{"salvatore", "sal"},
	{"sam", "sammy", "samuel"},
	{"samantha", "sammy", "sam", "mantha"},
	{"sammy", "samuel"},
	{"sampson", "sam"},
	{"samson", "sam"},
	{"samuel", "sam", "sammy"},
	{"samyra", "myra"},
	{"sandra", "sandy", "cassandra"},
	{"sandy", "sandra"},
	{"sanford", "sandy"},
	{"sarah", "sally", "sadie"},
	{"sarilla", "silla"},
	{"savannah", "vannie", "anna"},
	{"scott", "scotty", "sceeter", "squat", "scottie"},
	{"sebastian", "sebby", "seb"},
	{"selma", "anselm"},
	{"serena", "rena"},
	{"serilla", "rilla"},
	{"seymour", "see", "morey"},
	{"shaina", "sha", "shay"},
	{"sharon", "sha", "shay"},
	{"sheila", "cecilia"},
	{"sheldon", "shelly"},
	{"shelton", "tony", "shel", "shelly"},
	{"sheridan", "dan", "danny", "sher"},
	{"sheryl", "sher"},
	{"shirley", "sherry", "lee", "shirl"},
	{"sibbilla", "sybill", "sibbie", "sibbell"},
	{"sidney", "syd", "sid"},
	{"sigfired", "sid"},
	{"sigfrid", "sid"},
	{"sigismund", "sig"},
	{"silas", "si"},
	{"silence", "liley"},
	{"silvester", "vester", "si", "sly", "vest", "syl"},
	{"simeon", "si", "sion"},
	{"simon", "si", "sion"},
	{"simon", "si"},
	{"sly", "sylvester"},
	{"smith", "smitty"},
	{"socrates", "crate"},
	{"solomon", "sal", "salmon", "sol", "solly", "saul", "zolly"},
	{"sondra", "dre", "sonnie"},
	{"sophia", "sophie"},
	{"sophronia", "frona", "sophia", "fronia"},
	{"stephan", "steve"},
	{"stephanie", "stephen", "stephie", "annie", "steph"},
	{"stephen", "steve", "steph"},
	{"stephen", "steven", "steve", "ste"},
	{"steve", "stephen", "steven"},
	{"steven", "stephen", "steve", "ste"},
	{"steven", "steve", "steph"},
	{"stewart", "stu"},
	{"stuart", "stu"},
	{"sue", "susie", "susan"},
	{"sullivan", "sully", "van"},
	{"sully", "sullivan"},
	{"susan", "hannah", "susie", "sue", "sukey", "suzie"},
	{"susan", "suzie", "sue", "suze"},
	{"susannah", "hannah", "susie", "sue", "sukey"},
	{"susie", "suzie"},
	{"suzanne", "suki", "sue", "susie"},
	{"sybill", "sibbie"},
	{"sydney", "sid"},
	{"sylvanus", "sly", "syl"},
	{"sylvester", "sy", "sly", "vet", "syl", "vester", "si", "vessie"},
	{"tabby", "tabitha"},
	{"tabitha", "tabby"},
	{"tamarra", "tammy"},
	{"tanafra", "tanny"},
	{"tasha", "tash", "tashie"},
	{"ted", "teddy"},
	{"temperance", "tempy"},
	{"terence", "terry"},
	{"teresa", "terry"},
	{"terry", "terence"},
	{"tess", "teresa", "theresa"},
	{"tessa", "teresa", "theresa"},
	{"thad", "thaddeus"},
	{"thaddeus", "thad"},
	{"theo", "theodore"},
	{"theodora", "dora"},
	{"theodore", "theo", "ted", "teddy"},
	{"theodosia", "theo", "dosia", "theodosius"},
	{"theophilus", "ophi"},
	{"theotha", "otha"},
	{"theresa", "tessie", "thirza", "tessa", "terry", "tracy", "tess", "thursa"},
	{"thom", "thomas", "tommy", "tom"},
	{"thomas", "thom", "tommy", "tom"},
	{"thomas", "tom", "tommy"},
	{"thomasa", "tamzine"},
	{"tiffany", "tiff", "tiffy"},
	{"tilford", "tillie"},
	{"tim", "timothy", "timmy"},
	{"timmy", "timothy"},
	{"timothy", "tim", "timmy"},
	{"tina", "christina"},
	{"tobias", "bias", "toby"},
	{"tom", "thomas", "tommy"},
	{"tommy", "thomas"},
	{"tony", "anthony"},
	{"tranquilla", "trannie", "quilla"},
	{"trisha", "patricia"},
	{"trix", "trixie"},
	{"trudy", "gertrude"},
	{"tryphena", "phena"},
	{"unice", "eunice", "nicie"},
	{"uriah", "riah"},
	{"ursula", "sulie", "sula"},
	{"valentina", "felty", "vallie", "val"},
	{"valentine", "felty"},
	{"valeri", "val"},
	{"valerie", "val"},
	{"vanburen", "buren"},
	{"vandalia", "vannie"},
	{"vanessa", "essa", "vanna", "nessa"},
	{"vernisee", "nicey"},
	{"veronica", "vonnie", "ron", "ronna", "ronie", "frony", "franky", "ronnie"},
	{"vic", "vicki", "victor", "vicky"},
	{"vicki", "vicky", "victoria"},
	{"vickie", "victoria"},
	{"vicky", "victoria"},
	{"victor", "vic"},
	{"victoria", "torie", "vic", "vicki", "tory", "vicky"},
	{"victoria", "vicky", "vic"},
	{"vin", "vinny"},
	{"vince", "vinnie"},
	{"vincent", "vic", "vince", "vinnie", "vin", "vinny"},
	{"vincenzo", "vic", "vinnie", "vin", "vinny"},
	{"vinson", "vinny"},
	{"viola", "ola", "vi"},
	{"violetta", "lettie"},
	{"virginia", "Ginny"},
	{"virginia", "jane", "jennie", "ginny", "virgy", "ginger"},
	{"vivian", "vi", "viv"},
	{"waldo", "ozzy", "ossy"},
	{"wallace", "wally"},
	{"wally", "walt"},
	{"walter", "wally", "walt"},
	{"washington", "wash"},
	{"webster", "webb"},
	{"wendy", "wen"},
	{"wilber", "will", "bert"},
	{"wilbur", "willy", "willie"},
	{"wilda", "willie"},
	{"wilfred", "will", "willie", "fred"},
	{"wilhelmina", "mina", "wilma", "willie", "minnie"},
	{"will", "bill", "willie", "wilbur", "fred"},
	{"william", "bill", "billy", "willy", "bell", "bela", "will", "willie", "willy"},
	{"willie", "william", "fred"},
	{"willis", "willy", "bill"},
	{"wilma", "william", "billiewilhelm"},
	{"wilson", "will", "willy", "willie"},
	{"winfield", "field", "winny", "win"},
	{"winifred", "freddie", "winnie", "winnet"},
	{"winnie", "winnifred"},
	{"winnifred", "freddie", "freddy", "winny", "winnie", "fred"},
	{"winny", "winnifred"},
	{"winton", "wint"},
	{"woodrow", "woody", "wood", "drew"},
	{"yeona", "onie", "ona"},
	{"yvonne", "vonna"},
	{"zachariah", "zachy", "zach", "zeke", "zack"},
	{"zebedee", "zeb"},
	{"zedediah", "dyer", "zed", "diah"},
	{"zephaniah", "zeph"},
}
