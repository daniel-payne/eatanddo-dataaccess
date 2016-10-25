-----------------------------------------------------------------------------------------------------------------------------------------------------
--Drops
-----------------------------------------------------------------------------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetDays'                            AND type = 'P') DROP PROCEDURE diary.GetDays
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetDetails'                         AND type = 'P') DROP PROCEDURE diary.GetDetails

IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'PostFoodEntry'                      AND type = 'P') DROP PROCEDURE diary.PostFoodEntry
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'ProcessCalculateDay'                AND type = 'P') DROP PROCEDURE diary.ProcessCalculateDay
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'ProcessUpdateDay'                   AND type = 'P') DROP PROCEDURE diary.ProcessUpdateDay
                                                                                      
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetFoods'                           AND type = 'P') DROP PROCEDURE search.GetFoods
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetFoodNames'                       AND type = 'P') DROP PROCEDURE search.GetFoodNames
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'ProcessIndexFood'                   AND type = 'P') DROP PROCEDURE search.ProcessIndexFood
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'ProcessIndexMissingFoods'           AND type = 'P') DROP PROCEDURE search.ProcessIndexMissingFoods
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetUnits'                           AND type = 'P') DROP PROCEDURE search.GetUnits
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetFoodEntryCalculation'            AND type = 'P') DROP PROCEDURE search.GetFoodEntryCalculation

IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetAuthorizationForAnonymousUser'   AND type = 'P') DROP PROCEDURE security.GetAuthorizationForAnonymousUser
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetAuthorizationForExistingUser'    AND type = 'P') DROP PROCEDURE security.GetAuthorizationForExistingUser
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetAuthorizationForNewUser'         AND type = 'P') DROP PROCEDURE security.GetAuthorizationForNewUser
IF EXISTS (SELECT 1 FROM sysobjects WHERE name = 'GetAuthorizationForRegisteringUser' AND type = 'P') DROP PROCEDURE security.GetAuthorizationForRegisteringUser

go

---------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForExistingUser 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
---------------------------------------------------------------------------------------------------
CREATE PROCEDURE security.GetAuthorizationForExistingUser
(
   @EMail           Varchar(255),
   @Password        Varchar(255),
   @IPAddress       Varchar(15),
   @KeepActiveHours int = 48
)
AS
--
DECLARE @EXPIRY_HOURS             integer;     SET @EXPIRY_HOURS             = @KeepActiveHours;
DECLARE @MAX_BAD_TRY_COUNT        integer;     SET @MAX_BAD_TRY_COUNT        = 4;
--
DECLARE
  @PasswordHash        varbinary(20),
  @PersonGUID          uniqueidentifier,
  @NewSessionGUID      uniqueidentifier,
  @SessionExpiresDate  DateTime                               
--
SET @SessionExpiresDate = dateadd(hour, @EXPIRY_HOURS, getutcdate())
--
SELECT
  @PasswordHash = hashbytes('SHA1', @Password)
--
SELECT                                                                   
  @PersonGUID      = PersonGUID      
FROM
  security.[PERSON]
WHERE                                                                   
  EMAil         = @EMail               AND
  PasswordHash  = @PasswordHash        AND
  IsLockedOut   = 0                    AND
  BadTryCount   < @MAX_BAD_TRY_COUNT
--
IF @PersonGUID IS NOT NULL BEGIN
  --
  UPDATE [Session] SET
    IsActive = 0 
  WHERE 
    PersonGUID = @PersonGUID             
  --
  SET @NewSessionGUID = newid()
  --
  INSERT INTO [Session] 
  (
  	SessionGUID, 
  	PersonGUID, 
	IsActive,
  	IPAddress, 
  	SessionExpiresUTC
  )
  VALUES
  (
  	@NewSessionGUID,
  	@PersonGUID,
	1,
  	@IPAddress,
  	@SessionExpiresDate
  ) 
  --
  SELECT
    cast(@NewSessionGUID as varchar(50)  )                                   'sessionGuid',
    convert(varchar(19), @SessionExpiresDate, 126)                           'authorizationExpires' 
END ELSE BEGIN
  --
  RAISERROR ('Password Or UserName are incorrect',0,0) 
END
--      
RETURN @@rowcount
go

GRANT EXECUTE ON security.GetAuthorizationForExistingUser TO eatandoData
GO

---------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForAnonymousUser '127.0.0.1'
-- security.GetAuthorizationForRegisteringUser 'B71E9679-C3C3-4D21-9004-2A44FC44EE42', 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
---------------------------------------------------------------------------------------------------
CREATE PROCEDURE security.GetAuthorizationForRegisteringUser
(
   @SessionGUID     uniqueidentifier,
   @EMail           Varchar(255),
   @Password        Varchar(255),
   @IPAddress       Varchar(15)
)
AS
DECLARE
  @PasswordHash        varbinary(20) 
--
SELECT
  @PasswordHash = hashbytes('SHA1', @Password)
--
IF EXISTS (SELECT 1 FROM security.Person WHERE EMail = @EMail) BEGIN
  --
  RAISERROR ('UserName is allready used',0,0) 

END ELSE BEGIN
  --
  UPDATE P SET 
    EMail        = @EMail,
    PasswordHash = @PasswordHash,
    IsAnynmous   = 0 
  FROM 
    security.Session S
  INNER JOIN
    security.Person  P ON P.PersonGUID = S.PersonGUID 
  WHERE 
    SessionGUID = @SessionGUID
  --
  EXECUTE security.GetAuthorizationForExistingUser @EMail, @Password, @IPAddress 

END

--      
RETURN @@rowcount
go

GRANT EXECUTE ON security.GetAuthorizationForRegisteringUser TO eatandoData
GO

---------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForNewUser 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
---------------------------------------------------------------------------------------------------
CREATE PROCEDURE security.GetAuthorizationForNewUser
(
   @EMail           varchar(255),
   @Password        varchar(255),
   @IPAddress       Varchar(15)
)
AS
--
DECLARE
  @SessionGUID         uniqueidentifier,
  @PersonGUID          uniqueidentifier,
  @PasswordHash        varbinary(20)                                    
--
SELECT
  @PasswordHash = hashbytes('SHA1', @Password)
--
IF NOT EXISTS (SELECT 1 FROM [PERSON] WHERE EMail = @EMail) BEGIN
  --
  SET @PersonGUID  = newid()
  SET @SessionGUID = newid()
  --
  INSERT INTO security.[PERSON]  
  (
    PersonGUID, 
    EditCount,
    EMail, 
    PasswordHash, 
    CreatedUTC, 
    IsAnynmous,
    IsLockedOut, 
    BadTryCount 
  )
  VALUES
  (
    @PersonGUID,
    0,
    @EMail,
    @PasswordHash,
    getutcdate(),
    0,
    0,
    0  
  )
  --
  EXECUTE security.GetAuthorizationForExistingUser  @EMail, @Password, @IPAddress
END ELSE BEGIN
  --
  RAISERROR ('UserName Exists',0,0) 
END
--      
RETURN @@rowcount
go

GRANT EXECUTE ON security.GetAuthorizationForNewUser TO eatandoData
GO

---------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForAnonymousUser '127.0.0.1'
---------------------------------------------------------------------------------------------------
CREATE PROCEDURE security.GetAuthorizationForAnonymousUser
(
   @IPAddress       Varchar(15)
)
AS
DECLARE @EXPIRY_HOURS             integer       = 24*120;
DECLARE @MAX_BAD_TRY_COUNT        integer       = 4;
DECLARE @USER_NAME                varchar(255)  = CAST(CAST(RAND() * 1000000000 AS INTEGER) AS varchar(10));
--
DECLARE
  @EMail               Varchar(255)   = @USER_NAME + '@Anonymous.User',
  @Password            Varchar(255)   = @USER_NAME,
  @SessionGUID         uniqueidentifier,
  @PersonGUID          uniqueidentifier,
  @PasswordHash        varbinary(20)                                    
--
SELECT
  @PasswordHash = hashbytes('SHA1', @Password)
--
IF NOT EXISTS (SELECT 1 FROM [PERSON] WHERE EMail = @EMail) BEGIN
  --
  SET @PersonGUID  = newid()
  SET @SessionGUID = newid()
  --
  INSERT INTO security.[PERSON]  
  (
    PersonGUID, 
    EditCount,
    EMail, 
    PasswordHash, 
    CreatedUTC,
    IsAnynmous, 
    IsLockedOut, 
    BadTryCount 
  )
  VALUES
  (
    @PersonGUID,
    0,
    @EMail,
    @PasswordHash,
    getutcdate(),
    1,
    0,
    0  
  )
  --
  EXECUTE security.GetAuthorizationForExistingUser  @EMail, @Password, @IPAddress, @EXPIRY_HOURS 
END ELSE BEGIN
  --
  RAISERROR ('UserName Exists',0,0) 
END
--      
RETURN @@rowcount
go

GRANT EXECUTE ON security.GetAuthorizationForAnonymousUser TO eatandoData
GO


---------------------------------------------------------------------------------------------------------------------------------------------------
-- search.ProcessIndexFood 'D8895098-8D29-4C6F-A998-70375BF86D07' 
----------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.ProcessIndexFood 
(
  @FoodID          integer
)
AS
                                                                       
DECLARE
  @FoodName        varchar(255),
  @ProcessedName   varchar(255)

SELECT 
  @FoodName = FoodName + ' ' + ISNULL([BrandName], '') + ' ' + ISNULL([BrandShortName], '') 
FROM 
  search.Food 
WHERE
 FoodID = @FoodID

DELETE FROM
  search.FoodWord
WHERE
 FoodID = @FoodID

INSERT INTO search.FoodWord  (FoodID, WordIndex)
  SELECT DISTINCT 
    @FoodID, 
    dbo.TextToBigInteger(Word) 
  FROM 
    dbo.ProcessedWordsToTable(@FoodName)
RETURN @@ROWCOUNT
go

REVOKE EXECUTE ON search.ProcessIndexFood TO eatandoData
GO

---------------------------------------------------------------------------------------------------------------------------------------------------
-- search.ProcessIndexMissingFoods
----------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.ProcessIndexMissingFoods 
AS

DECLARE 
  @FoodID integer

DECLARE FOOD_CURSOR CURSOR FOR  
  SELECT  
    FoodID
  FROM
    search.food
  WHERE
    FoodID NOT IN (SELECT FoodID FROM search.FoodWord)

OPEN FOOD_CURSOR   
FETCH NEXT FROM FOOD_CURSOR INTO @FoodID   

WHILE @@FETCH_STATUS = 0   
BEGIN   
    EXECUTE search.ProcessIndexFood @FoodID

    FETCH NEXT FROM FOOD_CURSOR INTO @FoodID   
END   

CLOSE FOOD_CURSOR   
DEALLOCATE FOOD_CURSOR
GO

REVOKE EXECUTE ON search.ProcessIndexMissingFoods TO eatandoData
GO

---------------------------------------------------------------------------------------------------------------------------------------------------
-- search.GetMatchingFoodNames 'pork,pie' 
----------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.GetFoodNames 
(
   @Match      varchar(max)  ,
   @Sources    varchar(max)  = null,
   @MaxResults integer       = 10
)
AS

DECLARE @WORDS TABLE
(
   WordIndex bigint
)

DECLARE @MATCHES TABLE
(
   FoodID integer
)

DECLARE @RESULTS TABLE
(
   FoodID          integer,
   ExtraWordCount  integer
)

DECLARE 
  @ProcessedSearch     varchar(max),
  @WordIndex           bigint,
  @WordCount           int,
  @TotalResults        integer

INSERT INTO @WORDS
SELECT DISTINCT  
  dbo.TextToBigInteger(Word) 
FROM 
  dbo.ProcessedWordsToTable(@Match)

SELECT
  @WordCount = count(*)
FROM
  @WORDS

WHILE EXISTS (SELECT 1 FROM @WORDS) BEGIN

  SELECT TOP 1 @WordIndex = WordIndex FROM @WORDS

  DELETE FROM @WORDS WHERE WordIndex = @WordIndex

  INSERT INTO @MATCHES
    SELECT 
      FoodID
    FROM
      search.FoodWord 
    WHERE
      WordIndex = @WordIndex

END

INSERT INTO @RESULTS
    SELECT
      FoodID,
      null  
    FROM
      @MATCHES
    GROUP BY
      FoodID
    HAVING
      count(FoodID) >= @WordCount

UPDATE R SET
  ExtraWordCount = E.ExtraWordCount 
FROM
  @RESULTS R
INNER JOIN
(
  SELECT
    FoodID, 
    count(*) - @WordCount 'ExtraWordCount' 
  FROM
    @MATCHES 
  GROUP BY
    FoodID
) E ON E.FoodID = R.FoodID


SELECT
  @TotalResults = count(*)
FROM
  @RESULTS

DECLARE @OUTPUT TABLE
(
  FoodID            integer,

  FoodName          varchar(255),
  BrandName         varchar(255),
  SourceName        varchar(255),
  ServingUnitName   varchar(255),

  HasNutritionWeightInformation  bit,
  HasNutritionVolumeInformation  bit,
  HasNutritionServingInformation bit,
  HasNutritionPortionInformation bit,

  rowNumber         integer
) 

INSERT INTO @OUTPUT
SELECT  
  F.FoodID,
  F.FoodName,
  F.BrandName,
  F.SourceName,
  F.ServingUnitName, 
  F.HasNutritionWeightInformation, 
  F.HasNutritionVolumeInformation,  
  F.HasNutritionServingInformation,  
  F.HasNutritionPortionInformation,
  row_number() OVER(ORDER BY R.ExtraWordCount, datalength(F.FoodName )) AS rowNumber 
FROM
  search.Food F  WITH (INDEX(FoodCKDataForSearch))
INNER JOIN
  @RESULTS    R ON R.FoodID = F.FoodID
WHERE
  F.IsActive = 1
ORDER BY
  R.ExtraWordCount         ASC, 
  datalength(F.FoodName )  ASC

IF datalength(ISNULL(@Sources,'')) = 0 BEGIN
  SELECT TOP (ISNULL(@MaxResults, 999))
    FoodID                          'foodId', 
    FoodName                        'foodName', 
    BrandName                       'brandName', 
    SourceName                      'sourceName', 
    ServingUnitName                 'servingUnitName',
    HasNutritionWeightInformation   'hasNutritionWeightInformation',
    HasNutritionVolumeInformation   'hasNutritionVolumeInformation',
    HasNutritionServingInformation  'hasNutritionServingInformation',
    HasNutritionPortionInformation  'hasNutritionPortionInformation'
  FROM
    @OUTPUT
  ORDER BY
    rowNumber
END ELSE BEGIN
  SELECT TOP (ISNULL(@MaxResults, 999))
    FoodID                          'foodId', 
    FoodName                        'foodName', 
    BrandName                       'brandName', 
    SourceName                      'sourceName', 
    ServingUnitName                 'servingUnitName',
    HasNutritionWeightInformation   'hasNutritionWeightInformation',
    HasNutritionVolumeInformation   'hasNutritionVolumeInformation',
    HasNutritionServingInformation  'hasNutritionServingInformation',
    HasNutritionPortionInformation  'hasNutritionPortionInformation'
  FROM
    @OUTPUT
  WHERE
    charindex(SourceName, @Sources) > 0
  ORDER BY
    rowNumber
END

RETURN @TotalResults
go

GRANT EXECUTE ON search.GetFoodNames TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- search.GetFoods 'D6AE4790-C195-49C4-BB49-70EF20CD3F74, C756C011-E244-41F7-8AE8-94226BA21980, D8895098-8D29-4C6F-A998-70375BF86D07'
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.GetFoods
(
   @IDS varchar(max)  
)
AS
SELECT
	FoodID                             'foodId',
	FoodName                           'foodName',
	SourceName                         'sourceName',
	Barcode                            'barcode',
	CategoryName                       'categoryName',
	CategoryHierarchy                  'categoryHierarchy',
	BrandName                          'brandName',
	BrandShortName                     'brandShortName',
	GTN                                'gtn',
	ServingAmount                      'servingAmount',
	ServingUnitName                    'servingUnitName',
	ServingWeightGrams                 'servingWeightGrams',
	ServingVolumeMilliliters           'servingVolumeMilliliters',
	ContainerWeightGrams               'containerWeightGrams',
	ContainerVolumeMilliliters         'containerVolumeMilliliters',
	ContainerPortionsPerContainer      'containerPortionsPerContainer',
	EnergyCaloriesPer100g              'energyCaloriesPer100g',
	EnergyKiloJoulesPer100g            'energyKiloJoulesPer100g',
	ProteinGramsPer100g                'proteinGramsPer100g',
	CarbohydrateGramsPer100g           'carbohydrateGramsPer100g',
	SugarGramsPer100g                  'sugarGramsPer100g',
	StarchGramsPer100g                 'starchGramsPer100g',
	FatGramsPer100g                    'fatGramsPer100g',
	SaturatedFatGramsPer100g           'saturatedFatGramsPer100g',
	UnsaturatedFatGramsPer100g         'unsaturatedFatGramsPer100g',
	CholesterolGramsPer100g            'cholesterolGramsPer100g',
	TransFatGramsPer100g               'transFatGramsPer100g',
	DietaryFibreGramsPer100g           'dietaryFibreGramsPer100g',
	SolubleFibreGramsPer100g           'solubleFibreGramsPer100g',
	InsolubleFibreGramsPer100g         'insolubleFibreGramsPer100g',
	SaltGramsPer100g                   'saltGramsPer100g',
	SodiumGramsPer100g                 'sodiumGramsPer100g',
	AlcoholGramsPer100g                'alcoholGramsPer100g',
	EnergyCaloriesPer100ml             'energyCaloriesPer100ml',
	EnergyKiloJoulesPer100ml           'energyKiloJoulesPer100ml',
	ProteinGramsPer100ml               'proteinGramsPer100ml',
	CarbohydrateGramsPer100ml          'carbohydrateGramsPer100ml',
	SugarGramsPer100ml                 'sugarGramsPer100ml',
	StarchGramsPer100ml                'starchGramsPer100ml',
	FatGramsPer100ml                   'fatGramsPer100ml',
	SaturatedFatGramsPer100ml          'saturatedFatGramsPer100ml',
	UnsaturatedFatGramsPer100ml        'unsaturatedFatGramsPer100ml',
	CholesterolGramsPer100ml           'cholesterolGramsPer100ml',
	TransFatGramsPer100ml              'transFatGramsPer100ml',
	DietaryFibreGramsPer100ml          'dietaryFibreGramsPer100ml',
	SolubleFibreGramsPer100ml          'solubleFibreGramsPer100ml',
	InsolubleFibreGramsPer100ml        'insolubleFibreGramsPer100ml',
	SaltGramsPer100ml                  'saltGramsPer100ml',
	SodiumGramsPer100ml                'sodiumGramsPer100ml',
	AlcoholGramsPer100ml               'alcoholGramsPer100ml',
	EnergyCaloriesPerPortion           'energyCaloriesPerPortion',
	EnergyKiloJoulesPerPortion         'energyKiloJoulesPerPortion',
	ProteinGramsPerPortion             'proteinGramsPerPortion',
	CarbohydrateGramsPerPortion        'carbohydrateGramsPerPortion',
	SugarGramsPerPortion               'sugarGramsPerPortion',
	StarchGramsPerPortion              'starchGramsPerPortion',
	FatGramsPerPortion                 'fatGramsPerPortion',
	SaturatedFatGramsPerPortion        'saturatedFatGramsPerPortion',
	UnsaturatedFatGramsPerPortion      'unsaturatedFatGramsPerPortion',
	CholesterolGramsPerPortion         'cholesterolGramsPerPortion',
	TransFatGramsPerPortion            'transFatGramsPerPortion',
	DietaryFibreGramsPerPortion        'dietaryFibreGramsPerPortion',
	SolubleFibreGramsPerPortion        'solubleFibreGramsPerPortion',
	InsolubleFibreGramsPerPortion      'insolubleFibreGramsPerPortion',
	SaltGramsPerPortion                'saltGramsPerPortion',
	SodiumGramsPerPortion              'sodiumGramsPerPortion',
	AlcoholGramsPerPortion             'alcoholGramsPerPortion',
	HasNutritionWeightInformation      'hasNutritionWeightInformation',
	HasNutritionVolumeInformation      'hasNutritionVolumeInformation',
	HasNutritionServingInformation     'hasNutritionServingInformation',
	HasNutritionPortionInformation     'hasNutritionPortionInformation'
FROM
  search.food
WHERE
  IsActive = 1
AND
  foodID IN
(
  SELECT 
   cast(item as integer) 
  FROM 
    dbo.ListToTable(@IDS, ',')
)
RETURN @@ROWCOUNT
go

GRANT EXECUTE ON search.GetFoods TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- search.GetUnits 1
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.GetUnits
(
   @ShowFullDetails bit = 1  
)
AS

IF @ShowFullDetails = 1 BEGIN
  SELECT 
    UnitID           'UnitId', 
    UnitTypeName     'UnitTypeName', 
    UnitName         'UnitName', 
    ShortName        'ShortName', 
    PluralName       'PluralName', 
    DisplayName      'DisplayName', 
    Ratio            'Ratio' 
  FROM 
    search.Unit
  WHERE
    IsActive = 1

END ELSE BEGIN
  SELECT 
    UnitID           'UnitId'   
  FROM 
    search.Unit
  WHERE
    IsActive = 1

END

RETURN @@ROWCOUNT
go

GRANT EXECUTE ON search.GetUnits TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- search.GetFoodEntryCalculation 10989, 120, 'g'
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE search.GetFoodEntryCalculation
(

   @FoodID          integer,
   @Amount          float,
   @UnitName        varchar(255)
)
AS

DECLARE
  @FoodName varchar(255)

SELECT
  @FoodName = FoodName 
FROM
  search.Food
WHERE
  FoodID = @FoodID

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
DECLARE @SODIUM_TO_SALT_CONVERSION         float = 2.5000 
DECLARE @CALORIES_TO_KILOJOULES_CONVERSION float = 4.1840

DECLARE

  @BaselineDescription               varchar(255),
  @UnitDescription                   varchar(255),

  @InputType                         varchar(255),
  @InputRatio                        float,
                                     
  @BaselineType                      varchar(255),
  @BaselineRatio                     float,
  @BaselineAmount                    float,

  @EnergyKiloJoulesPerBaseline       float,
  @ProteinGramsPerBaseline           float,
  @CarbohydrateGramsPerBaseline      float,
  @SugarGramsPerBaseline             float,
  @StarchGramsPerBaseline            float,
  @FatGramsPerBaseline               float,
  @SaturatedFatGramsPerBaseline      float,
  @UnsaturatedFatGramsPerBaseline    float,
  @CholesterolGramsPerBaseline       float,
  @TransFatGramsPerBaseline          float,
  @DietaryFibreGramsPerBaseline      float,
  @SolubleFibreGramsPerBaseline      float,
  @InsolubleFibreGramsPerBaseline    float,
  @SodiumGramsPerBaseline            float,
  @AlcoholGramsPerBaseline           float,

  @EnergyKiloJoulesPerEntry          float,
  @ProteinGramsPerEntry              float,
  @CarbohydrateGramsPerEntry         float,
  @SugarGramsPerEntry                float,
  @StarchGramsPerEntry               float,
  @FatGramsPerEntry                  float,
  @SaturatedFatGramsPerEntry         float,
  @UnsaturatedFatGramsPerEntry       float,
  @CholesterolGramsPerEntry          float,
  @TransFatGramsPerEntry             float,
  @DietaryFibreGramsPerEntry         float,
  @SolubleFibreGramsPerEntry         float,
  @InsolubleFibreGramsPerEntry       float,
  @SodiumGramsPerEntry               float,
  @AlcoholGramsPerEntry              float


IF UPPER(@UnitName) = 'PORTION' BEGIN

  SET @UnitDescription     = 'Portion'
  SET @InputType           = 'PORTION'
  SET @InputRatio          = 1

END ELSE BEGIN

  SELECT
    @UnitDescription   = CASE WHEN @Amount <= 1 THEN ISNULL(DisplayName, UnitName) ELSE ISNULL(DisplayName, PluralName) END,
    @InputType         = UPPER(UnitTypeName),
    @InputRatio        = Ratio / 100.00
  FROM
    search.Unit
  WHERE
    UPPER(UnitName)          =  UPPER(@UnitName) OR
    UPPER(ShortName)         =  UPPER(@UnitName) OR
    UPPER(PluralName)        =  UPPER(@UnitName) OR
    UPPER(DisplayName)       =  UPPER(@UnitName) 
  AND
    UnitTypeName IN ('weight', 'volume')  

END

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

IF @InputType IS NULL BEGIN
  
  SELECT
    @UnitDescription   = ServingUnitName,
    @InputType         = CASE WHEN UPPER(ServingUnitName) = UPPER(dbo.PluralToSingular(@UnitName)) THEN 'SERVING' END,
    @InputRatio        = ServingWeightGrams / 100.00
  FROM
    search.Food
  WHERE
    FoodID = @FoodID AND
    ServingWeightGrams IS NOT NULL

  IF @InputType IS NOT NULL
    SET @BaselineType = 'WEIGHT'
    
  IF @Amount >= 2 BEGIN

     IF UPPER(SUBSTRING(REVERSE(@UnitDescription),1,1)) != 'S' BEGIN

       SET @UnitDescription = @UnitDescription + 's'

     END

  END
END 

IF @InputType IS NULL BEGIN
  
  SELECT
    @UnitDescription   = ServingUnitName,
    @InputType         = CASE WHEN UPPER(ServingUnitName) = UPPER(dbo.PluralToSingular(@UnitName)) THEN 'SERVING' END,
    @InputRatio        = ServingVolumeMilliliters / 100.00
  FROM
    search.Food
  WHERE
    FoodID = @FoodID AND
    ServingVolumeMilliliters IS NOT NULL

  IF @InputType IS NOT NULL
    SET @BaselineType = 'VOLUME'
  
    IF @Amount >= 2 BEGIN

     IF UPPER(SUBSTRING(REVERSE(@UnitDescription),1,1)) != 'S' BEGIN

       SET @UnitDescription = @UnitDescription + 's'

     END

  END  

END 

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

IF @BaselineType IS NULL BEGIN

  SET @BaselineType = @InputType

END 

SET @BaselineRatio = @InputRatio

SET @BaselineAmount =  @BaselineRatio * @Amount

IF @BaselineType = 'WEIGHT' BEGIN

  SET @BaselineDescription = '100g'

  SELECT 	
	  @EnergyKiloJoulesPerBaseline    = ISNULL(EnergyKiloJoulesPer100g, (EnergyCaloriesPer100g * @CALORIES_TO_KILOJOULES_CONVERSION)),  
	  @ProteinGramsPerBaseline        = ProteinGramsPer100g,  
	  @CarbohydrateGramsPerBaseline   = CarbohydrateGramsPer100g,
	  @SugarGramsPerBaseline          = SugarGramsPer100g,
	  @StarchGramsPerBaseline         = StarchGramsPer100g, 
	  @FatGramsPerBaseline            = FatGramsPer100g,
	  @SaturatedFatGramsPerBaseline   = SaturatedFatGramsPer100g,
	  @UnsaturatedFatGramsPerBaseline = UnsaturatedFatGramsPer100g, 
	  @CholesterolGramsPerBaseline    = CholesterolGramsPer100g, 
	  @TransFatGramsPerBaseline       = TransFatGramsPer100g, 
	  @DietaryFibreGramsPerBaseline   = DietaryFibreGramsPer100g,
	  @SolubleFibreGramsPerBaseline   = SolubleFibreGramsPer100g, 
	  @InsolubleFibreGramsPerBaseline = InsolubleFibreGramsPer100g,   
	  @SodiumGramsPerBaseline         = ISNULL(SodiumGramsPer100g, SaltGramsPer100g / @SODIUM_TO_SALT_CONVERSION),
	  @AlcoholGramsPerBaseline        = AlcoholGramsPer100g 
  FROM
    search.Food
  WHERE
    FoodID = @FoodID      

END ELSE IF @BaselineType = 'VOLUME' BEGIN

  SET @BaselineDescription = '100ml'

  SELECT 	
	  @EnergyKiloJoulesPerBaseline    = ISNULL(EnergyKiloJoulesPer100ml, (EnergyCaloriesPer100ml * @CALORIES_TO_KILOJOULES_CONVERSION)),  
	  @ProteinGramsPerBaseline        = ProteinGramsPer100ml,  
	  @CarbohydrateGramsPerBaseline   = CarbohydrateGramsPer100ml,
	  @SugarGramsPerBaseline          = SugarGramsPer100ml,
	  @StarchGramsPerBaseline         = StarchGramsPer100ml, 
	  @FatGramsPerBaseline            = FatGramsPer100ml,
	  @SaturatedFatGramsPerBaseline   = SaturatedFatGramsPer100ml,
	  @UnsaturatedFatGramsPerBaseline = UnsaturatedFatGramsPer100ml, 
	  @CholesterolGramsPerBaseline    = CholesterolGramsPer100ml, 
	  @TransFatGramsPerBaseline       = TransFatGramsPer100ml, 
	  @DietaryFibreGramsPerBaseline   = DietaryFibreGramsPer100ml,
	  @SolubleFibreGramsPerBaseline   = SolubleFibreGramsPer100ml, 
	  @InsolubleFibreGramsPerBaseline = InsolubleFibreGramsPer100ml,   
	  @SodiumGramsPerBaseline         = ISNULL(SodiumGramsPer100ml, SaltGramsPer100ml / @SODIUM_TO_SALT_CONVERSION),
	  @AlcoholGramsPerBaseline        = AlcoholGramsPer100ml 
  FROM
    search.Food
  WHERE
    FoodID = @FoodID      

END ELSE IF @BaselineType = 'PORTION' BEGIN

  SET @BaselineDescription = 'portion'

  SELECT 	
	  @EnergyKiloJoulesPerBaseline    = ISNULL(EnergyKiloJoulesPerPortion, (EnergyCaloriesPerPortion * @CALORIES_TO_KILOJOULES_CONVERSION)),  
	  @ProteinGramsPerBaseline        = ProteinGramsPerPortion,  
	  @CarbohydrateGramsPerBaseline   = CarbohydrateGramsPerPortion,
	  @SugarGramsPerBaseline          = SugarGramsPerPortion,
	  @StarchGramsPerBaseline         = StarchGramsPerPortion, 
	  @FatGramsPerBaseline            = FatGramsPerPortion,
	  @SaturatedFatGramsPerBaseline   = SaturatedFatGramsPerPortion,
	  @UnsaturatedFatGramsPerBaseline = UnsaturatedFatGramsPerPortion, 
	  @CholesterolGramsPerBaseline    = CholesterolGramsPerPortion, 
	  @TransFatGramsPerBaseline       = TransFatGramsPerPortion, 
	  @DietaryFibreGramsPerBaseline   = DietaryFibreGramsPerPortion,
	  @SolubleFibreGramsPerBaseline   = SolubleFibreGramsPerPortion, 
	  @InsolubleFibreGramsPerBaseline = InsolubleFibreGramsPerPortion,   
	  @SodiumGramsPerBaseline         = ISNULL(SodiumGramsPerPortion, SaltGramsPerPortion / @SODIUM_TO_SALT_CONVERSION),
	  @AlcoholGramsPerBaseline        = AlcoholGramsPerPortion 
  FROM
    search.Food
  WHERE
    FoodID = @FoodID      

END

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SET @EnergyKiloJoulesPerEntry        = @EnergyKiloJoulesPerBaseline       * @BaselineAmount
SET @ProteinGramsPerEntry            = @ProteinGramsPerBaseline           * @BaselineAmount
SET @CarbohydrateGramsPerEntry       = @CarbohydrateGramsPerBaseline      * @BaselineAmount
SET @SugarGramsPerEntry              = @SugarGramsPerBaseline             * @BaselineAmount
SET @StarchGramsPerEntry             = @StarchGramsPerBaseline            * @BaselineAmount
SET @FatGramsPerEntry                = @FatGramsPerBaseline               * @BaselineAmount
SET @SaturatedFatGramsPerEntry       = @SaturatedFatGramsPerBaseline      * @BaselineAmount
SET @UnsaturatedFatGramsPerEntry     = @UnsaturatedFatGramsPerBaseline    * @BaselineAmount
SET @CholesterolGramsPerEntry        = @CholesterolGramsPerBaseline       * @BaselineAmount
SET @TransFatGramsPerEntry           = @TransFatGramsPerBaseline          * @BaselineAmount
SET @DietaryFibreGramsPerEntry       = @DietaryFibreGramsPerBaseline      * @BaselineAmount
SET @SolubleFibreGramsPerEntry       = @SolubleFibreGramsPerBaseline      * @BaselineAmount
SET @InsolubleFibreGramsPerEntry     = @InsolubleFibreGramsPerBaseline    * @BaselineAmount
SET @SodiumGramsPerEntry             = @SodiumGramsPerBaseline            * @BaselineAmount
SET @AlcoholGramsPerEntry            = @AlcoholGramsPerBaseline           * @BaselineAmount

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SELECT
  @FoodID                             'foodId',

  CAST(@Amount as varchar(20)) + ' ' + 
  @UnitDescription                    'amountDescription',
  @FoodName                           'foodName', 
  
  @BaselineDescription                'baselineDescription',
                     
  
  @EnergyKiloJoulesPerEntry           'energyKiloJoulesPerEntry',
  @ProteinGramsPerEntry               'proteinGramsPerEntry',
  @CarbohydrateGramsPerEntry          'carbohydrateGramsPerEntry',
  @SugarGramsPerEntry                 'sugarGramsPerEntry',
  @StarchGramsPerEntry                'starchGramsPerEntry',
  @FatGramsPerEntry                   'fatGramsPerEntry',
  @SaturatedFatGramsPerEntry          'saturatedFatGramsPerEntry',
  @UnsaturatedFatGramsPerEntry        'unsaturatedFatGramsPerEntry',
  @CholesterolGramsPerEntry           'cholesterolGramsPerEntry',
  @TransFatGramsPerEntry              'transFatGramsPerEntry',
  @DietaryFibreGramsPerEntry          'dietaryFibreGramsPerEntry',
  @SolubleFibreGramsPerEntry          'solubleFibreGramsPerEntry',
  @InsolubleFibreGramsPerEntry        'insolubleFibreGramsPerEntry',
  @SodiumGramsPerEntry                'sodiumGramsPerEntry',
  @AlcoholGramsPerEntry               'alcoholGramsPerEntry',
                                    
  @EnergyKiloJoulesPerBaseline        'energyKiloJoulesPerBaseline',
  @ProteinGramsPerBaseline            'proteinGramsPerBaseline',
  @CarbohydrateGramsPerBaseline       'carbohydrateGramsPerBaseline',
  @SugarGramsPerBaseline              'sugarGramsPerBaseline',
  @StarchGramsPerBaseline             'starchGramsPerBaseline',
  @FatGramsPerBaseline                'fatGramsPerBaseline',
  @SaturatedFatGramsPerBaseline       'saturatedFatGramsPerBaseline',
  @UnsaturatedFatGramsPerBaseline     'unsaturatedFatGramsPerBaseline',
  @CholesterolGramsPerBaseline        'cholesterolGramsPerBaseline',
  @TransFatGramsPerBaseline           'transFatGramsPerBaseline',
  @DietaryFibreGramsPerBaseline       'dietaryFibreGramsPerBaseline',
  @SolubleFibreGramsPerBaseline       'solubleFibreGramsPerBaseline',
  @InsolubleFibreGramsPerBaseline     'insolubleFibreGramsPerBaseline',
  @SodiumGramsPerBaseline             'sodiumGramsPerBaseline',
  @AlcoholGramsPerBaseline            'alcoholGramsPerBaseline'

RETURN @@ROWCOUNT
go

GRANT EXECUTE ON search.GetFoodEntryCalculation TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE diary.ProcessCalculateDay
(
  @PersonGUID                       uniqueidentifier, 
  @DayDate                          date 
)
AS

  UPDATE diary.day SET 
    TotalEnergyKiloJoulesPerDay      = 0,
    TotalProteinGramsPerDay          = 0,
    TotalCarbohydrateGramsPerDay     = 0,
    TotalSugarGramsPerDay            = 0,
    TotalStarchGramsPerDay           = 0,
    TotalFatGramsPerDay              = 0,
    TotalSaturatedFatGramsPerDay     = 0,
    TotalUnsaturatedFatGramsPerDay   = 0,
    TotalCholesterolGramsPerDay      = 0,
    TotalTransFatGramsPerDay         = 0,
    TotalDietaryFibreGramsPerDay     = 0,
    TotalSolubleFibreGramsPerDay     = 0,
    TotalInsolubleFibreGramsPerDay   = 0,
    TotalSodiumGramsPerDay           = 0,
    TotalAlcoholGramsPerDay          = 0
  WHERE
    PersonGUID = @PersonGUID AND DayDate = @DayDate

  UPDATE diary.day SET 
    TotalEnergyKiloJoulesPerDay      = TotalEnergyKiloJoulesPerDay     + ISNULL(Breakfast01EnergyKiloJoulesPerEntry, 0)       + ISNULL(Breakfast02EnergyKiloJoulesPerEntry, 0)      + ISNULL(Breakfast03EnergyKiloJoulesPerEntry, 0)       + ISNULL(Breakfast04EnergyKiloJoulesPerEntry, 0)       + ISNULL(Breakfast05EnergyKiloJoulesPerEntry, 0)       + ISNULL(Breakfast06EnergyKiloJoulesPerEntry, 0)      + ISNULL(Breakfast07EnergyKiloJoulesPerEntry, 0)       + ISNULL(Breakfast08EnergyKiloJoulesPerEntry, 0)      + ISNULL(Breakfast09EnergyKiloJoulesPerEntry, 0)    + ISNULL(Breakfast10EnergyKiloJoulesPerEntry, 0)                      ,       
    TotalProteinGramsPerDay          = TotalProteinGramsPerDay         + ISNULL(Breakfast01ProteinGramsPerEntry, 0)           + ISNULL(Breakfast02ProteinGramsPerEntry, 0)          + ISNULL(Breakfast03ProteinGramsPerEntry, 0)           + ISNULL(Breakfast04ProteinGramsPerEntry, 0)           + ISNULL(Breakfast05ProteinGramsPerEntry, 0)           + ISNULL(Breakfast06ProteinGramsPerEntry, 0)          + ISNULL(Breakfast07ProteinGramsPerEntry, 0)           + ISNULL(Breakfast08ProteinGramsPerEntry, 0)          + ISNULL(Breakfast09ProteinGramsPerEntry, 0)        + ISNULL(Breakfast10ProteinGramsPerEntry, 0)                          ,
    TotalCarbohydrateGramsPerDay     = TotalCarbohydrateGramsPerDay    + ISNULL(Breakfast01CarbohydrateGramsPerEntry, 0)      + ISNULL(Breakfast02CarbohydrateGramsPerEntry, 0)     + ISNULL(Breakfast03CarbohydrateGramsPerEntry, 0)      + ISNULL(Breakfast04CarbohydrateGramsPerEntry, 0)      + ISNULL(Breakfast05CarbohydrateGramsPerEntry, 0)      + ISNULL(Breakfast06CarbohydrateGramsPerEntry, 0)     + ISNULL(Breakfast07CarbohydrateGramsPerEntry, 0)      + ISNULL(Breakfast08CarbohydrateGramsPerEntry, 0)     + ISNULL(Breakfast09CarbohydrateGramsPerEntry, 0)   + ISNULL(Breakfast10CarbohydrateGramsPerEntry, 0)                     ,
    TotalSugarGramsPerDay            = TotalSugarGramsPerDay           + ISNULL(Breakfast01SugarGramsPerEntry, 0)             + ISNULL(Breakfast02SugarGramsPerEntry, 0)            + ISNULL(Breakfast03SugarGramsPerEntry, 0)             + ISNULL(Breakfast04SugarGramsPerEntry, 0)             + ISNULL(Breakfast05SugarGramsPerEntry, 0)             + ISNULL(Breakfast06SugarGramsPerEntry, 0)            + ISNULL(Breakfast07SugarGramsPerEntry, 0)             + ISNULL(Breakfast08SugarGramsPerEntry, 0)            + ISNULL(Breakfast09SugarGramsPerEntry, 0)          + ISNULL(Breakfast10SugarGramsPerEntry, 0)                            ,
    TotalStarchGramsPerDay           = TotalStarchGramsPerDay          + ISNULL(Breakfast01StarchGramsPerEntry, 0)            + ISNULL(Breakfast02StarchGramsPerEntry, 0)           + ISNULL(Breakfast03StarchGramsPerEntry, 0)            + ISNULL(Breakfast04StarchGramsPerEntry, 0)            + ISNULL(Breakfast05StarchGramsPerEntry, 0)            + ISNULL(Breakfast06StarchGramsPerEntry, 0)           + ISNULL(Breakfast07StarchGramsPerEntry, 0)            + ISNULL(Breakfast08StarchGramsPerEntry, 0)           + ISNULL(Breakfast09StarchGramsPerEntry, 0)         + ISNULL(Breakfast10StarchGramsPerEntry, 0)                           ,
    TotalFatGramsPerDay              = TotalFatGramsPerDay             + ISNULL(Breakfast01FatGramsPerEntry, 0)               + ISNULL(Breakfast02FatGramsPerEntry, 0)              + ISNULL(Breakfast03FatGramsPerEntry, 0)               + ISNULL(Breakfast04FatGramsPerEntry, 0)               + ISNULL(Breakfast05FatGramsPerEntry, 0)               + ISNULL(Breakfast06FatGramsPerEntry, 0)              + ISNULL(Breakfast07FatGramsPerEntry, 0)               + ISNULL(Breakfast08FatGramsPerEntry, 0)              + ISNULL(Breakfast09FatGramsPerEntry, 0)            + ISNULL(Breakfast10FatGramsPerEntry, 0)                              ,
    TotalSaturatedFatGramsPerDay     = TotalSaturatedFatGramsPerDay    + ISNULL(Breakfast01SaturatedFatGramsPerEntry, 0)      + ISNULL(Breakfast02SaturatedFatGramsPerEntry, 0)     + ISNULL(Breakfast03SaturatedFatGramsPerEntry, 0)      + ISNULL(Breakfast04SaturatedFatGramsPerEntry, 0)      + ISNULL(Breakfast05SaturatedFatGramsPerEntry, 0)      + ISNULL(Breakfast06SaturatedFatGramsPerEntry, 0)     + ISNULL(Breakfast07SaturatedFatGramsPerEntry, 0)      + ISNULL(Breakfast08SaturatedFatGramsPerEntry, 0)     + ISNULL(Breakfast09SaturatedFatGramsPerEntry, 0)   + ISNULL(Breakfast10SaturatedFatGramsPerEntry, 0)                     ,
    TotalUnsaturatedFatGramsPerDay   = TotalUnsaturatedFatGramsPerDay  + ISNULL(Breakfast01UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Breakfast02UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Breakfast03UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Breakfast04UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Breakfast05UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Breakfast06UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Breakfast07UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Breakfast08UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Breakfast09UnsaturatedFatGramsPerEntry, 0) + ISNULL(Breakfast10UnsaturatedFatGramsPerEntry, 0)                   ,
    TotalCholesterolGramsPerDay      = TotalCholesterolGramsPerDay     + ISNULL(Breakfast01CholesterolGramsPerEntry, 0)       + ISNULL(Breakfast02CholesterolGramsPerEntry, 0)      + ISNULL(Breakfast03CholesterolGramsPerEntry, 0)       + ISNULL(Breakfast04CholesterolGramsPerEntry, 0)       + ISNULL(Breakfast05CholesterolGramsPerEntry, 0)       + ISNULL(Breakfast06CholesterolGramsPerEntry, 0)      + ISNULL(Breakfast07CholesterolGramsPerEntry, 0)       + ISNULL(Breakfast08CholesterolGramsPerEntry, 0)      + ISNULL(Breakfast09CholesterolGramsPerEntry, 0)    + ISNULL(Breakfast10CholesterolGramsPerEntry, 0)                      ,
    TotalTransFatGramsPerDay         = TotalTransFatGramsPerDay        + ISNULL(Breakfast01TransFatGramsPerEntry, 0)          + ISNULL(Breakfast02TransFatGramsPerEntry, 0)         + ISNULL(Breakfast03TransFatGramsPerEntry, 0)          + ISNULL(Breakfast04TransFatGramsPerEntry, 0)          + ISNULL(Breakfast05TransFatGramsPerEntry, 0)          + ISNULL(Breakfast06TransFatGramsPerEntry, 0)         + ISNULL(Breakfast07TransFatGramsPerEntry, 0)          + ISNULL(Breakfast08TransFatGramsPerEntry, 0)         + ISNULL(Breakfast09TransFatGramsPerEntry, 0)       + ISNULL(Breakfast10TransFatGramsPerEntry, 0)                         ,
    TotalDietaryFibreGramsPerDay     = TotalDietaryFibreGramsPerDay    + ISNULL(Breakfast01DietaryFibreGramsPerEntry, 0)      + ISNULL(Breakfast02DietaryFibreGramsPerEntry, 0)     + ISNULL(Breakfast03DietaryFibreGramsPerEntry, 0)      + ISNULL(Breakfast04DietaryFibreGramsPerEntry, 0)      + ISNULL(Breakfast05DietaryFibreGramsPerEntry, 0)      + ISNULL(Breakfast06DietaryFibreGramsPerEntry, 0)     + ISNULL(Breakfast07DietaryFibreGramsPerEntry, 0)      + ISNULL(Breakfast08DietaryFibreGramsPerEntry, 0)     + ISNULL(Breakfast09DietaryFibreGramsPerEntry, 0)   + ISNULL(Breakfast10DietaryFibreGramsPerEntry, 0)                     ,
    TotalSolubleFibreGramsPerDay     = TotalSolubleFibreGramsPerDay    + ISNULL(Breakfast01SolubleFibreGramsPerEntry, 0)      + ISNULL(Breakfast02SolubleFibreGramsPerEntry, 0)     + ISNULL(Breakfast03SolubleFibreGramsPerEntry, 0)      + ISNULL(Breakfast04SolubleFibreGramsPerEntry, 0)      + ISNULL(Breakfast05SolubleFibreGramsPerEntry, 0)      + ISNULL(Breakfast06SolubleFibreGramsPerEntry, 0)     + ISNULL(Breakfast07SolubleFibreGramsPerEntry, 0)      + ISNULL(Breakfast08SolubleFibreGramsPerEntry, 0)     + ISNULL(Breakfast09SolubleFibreGramsPerEntry, 0)   + ISNULL(Breakfast10SolubleFibreGramsPerEntry, 0)                     ,
    TotalInsolubleFibreGramsPerDay   = TotalInsolubleFibreGramsPerDay  + ISNULL(Breakfast01InsolubleFibreGramsPerEntry, 0)    + ISNULL(Breakfast02InsolubleFibreGramsPerEntry, 0)   + ISNULL(Breakfast03InsolubleFibreGramsPerEntry, 0)    + ISNULL(Breakfast04InsolubleFibreGramsPerEntry, 0)    + ISNULL(Breakfast05InsolubleFibreGramsPerEntry, 0)    + ISNULL(Breakfast06InsolubleFibreGramsPerEntry, 0)   + ISNULL(Breakfast07InsolubleFibreGramsPerEntry, 0)    + ISNULL(Breakfast08InsolubleFibreGramsPerEntry, 0)   + ISNULL(Breakfast09InsolubleFibreGramsPerEntry, 0) + ISNULL(Breakfast10InsolubleFibreGramsPerEntry, 0)                   ,
    TotalSodiumGramsPerDay           = TotalSodiumGramsPerDay          + ISNULL(Breakfast01SodiumGramsPerEntry, 0)            + ISNULL(Breakfast02SodiumGramsPerEntry, 0)           + ISNULL(Breakfast03SodiumGramsPerEntry, 0)            + ISNULL(Breakfast04SodiumGramsPerEntry, 0)            + ISNULL(Breakfast05SodiumGramsPerEntry, 0)            + ISNULL(Breakfast06SodiumGramsPerEntry, 0)           + ISNULL(Breakfast07SodiumGramsPerEntry, 0)            + ISNULL(Breakfast08SodiumGramsPerEntry, 0)           + ISNULL(Breakfast09SodiumGramsPerEntry, 0)         + ISNULL(Breakfast10SodiumGramsPerEntry, 0)                           ,
    TotalAlcoholGramsPerDay          = TotalAlcoholGramsPerDay         + ISNULL(Breakfast01AlcoholGramsPerEntry, 0)           + ISNULL(Breakfast02AlcoholGramsPerEntry, 0)          + ISNULL(Breakfast03AlcoholGramsPerEntry, 0)           + ISNULL(Breakfast04AlcoholGramsPerEntry, 0)           + ISNULL(Breakfast05AlcoholGramsPerEntry, 0)           + ISNULL(Breakfast06AlcoholGramsPerEntry, 0)          + ISNULL(Breakfast07AlcoholGramsPerEntry, 0)           + ISNULL(Breakfast08AlcoholGramsPerEntry, 0)          + ISNULL(Breakfast09AlcoholGramsPerEntry, 0)        + ISNULL(Breakfast10AlcoholGramsPerEntry, 0)                           
  WHERE
    PersonGUID = @PersonGUID AND DayDate = @DayDate

  UPDATE diary.day SET 
    TotalEnergyKiloJoulesPerDay      = TotalEnergyKiloJoulesPerDay     + ISNULL(Lunch01EnergyKiloJoulesPerEntry, 0)       + ISNULL(Lunch02EnergyKiloJoulesPerEntry, 0)      + ISNULL(Lunch03EnergyKiloJoulesPerEntry, 0)       + ISNULL(Lunch04EnergyKiloJoulesPerEntry, 0)       + ISNULL(Lunch05EnergyKiloJoulesPerEntry, 0)       + ISNULL(Lunch06EnergyKiloJoulesPerEntry, 0)      + ISNULL(Lunch07EnergyKiloJoulesPerEntry, 0)       + ISNULL(Lunch08EnergyKiloJoulesPerEntry, 0)      + ISNULL(Lunch09EnergyKiloJoulesPerEntry, 0)    + ISNULL(Lunch10EnergyKiloJoulesPerEntry, 0)                      ,       
    TotalProteinGramsPerDay          = TotalProteinGramsPerDay         + ISNULL(Lunch01ProteinGramsPerEntry, 0)           + ISNULL(Lunch02ProteinGramsPerEntry, 0)          + ISNULL(Lunch03ProteinGramsPerEntry, 0)           + ISNULL(Lunch04ProteinGramsPerEntry, 0)           + ISNULL(Lunch05ProteinGramsPerEntry, 0)           + ISNULL(Lunch06ProteinGramsPerEntry, 0)          + ISNULL(Lunch07ProteinGramsPerEntry, 0)           + ISNULL(Lunch08ProteinGramsPerEntry, 0)          + ISNULL(Lunch09ProteinGramsPerEntry, 0)        + ISNULL(Lunch10ProteinGramsPerEntry, 0)                          ,
    TotalCarbohydrateGramsPerDay     = TotalCarbohydrateGramsPerDay    + ISNULL(Lunch01CarbohydrateGramsPerEntry, 0)      + ISNULL(Lunch02CarbohydrateGramsPerEntry, 0)     + ISNULL(Lunch03CarbohydrateGramsPerEntry, 0)      + ISNULL(Lunch04CarbohydrateGramsPerEntry, 0)      + ISNULL(Lunch05CarbohydrateGramsPerEntry, 0)      + ISNULL(Lunch06CarbohydrateGramsPerEntry, 0)     + ISNULL(Lunch07CarbohydrateGramsPerEntry, 0)      + ISNULL(Lunch08CarbohydrateGramsPerEntry, 0)     + ISNULL(Lunch09CarbohydrateGramsPerEntry, 0)   + ISNULL(Lunch10CarbohydrateGramsPerEntry, 0)                     ,
    TotalSugarGramsPerDay            = TotalSugarGramsPerDay           + ISNULL(Lunch01SugarGramsPerEntry, 0)             + ISNULL(Lunch02SugarGramsPerEntry, 0)            + ISNULL(Lunch03SugarGramsPerEntry, 0)             + ISNULL(Lunch04SugarGramsPerEntry, 0)             + ISNULL(Lunch05SugarGramsPerEntry, 0)             + ISNULL(Lunch06SugarGramsPerEntry, 0)            + ISNULL(Lunch07SugarGramsPerEntry, 0)             + ISNULL(Lunch08SugarGramsPerEntry, 0)            + ISNULL(Lunch09SugarGramsPerEntry, 0)          + ISNULL(Lunch10SugarGramsPerEntry, 0)                            ,
    TotalStarchGramsPerDay           = TotalStarchGramsPerDay          + ISNULL(Lunch01StarchGramsPerEntry, 0)            + ISNULL(Lunch02StarchGramsPerEntry, 0)           + ISNULL(Lunch03StarchGramsPerEntry, 0)            + ISNULL(Lunch04StarchGramsPerEntry, 0)            + ISNULL(Lunch05StarchGramsPerEntry, 0)            + ISNULL(Lunch06StarchGramsPerEntry, 0)           + ISNULL(Lunch07StarchGramsPerEntry, 0)            + ISNULL(Lunch08StarchGramsPerEntry, 0)           + ISNULL(Lunch09StarchGramsPerEntry, 0)         + ISNULL(Lunch10StarchGramsPerEntry, 0)                           ,
    TotalFatGramsPerDay              = TotalFatGramsPerDay             + ISNULL(Lunch01FatGramsPerEntry, 0)               + ISNULL(Lunch02FatGramsPerEntry, 0)              + ISNULL(Lunch03FatGramsPerEntry, 0)               + ISNULL(Lunch04FatGramsPerEntry, 0)               + ISNULL(Lunch05FatGramsPerEntry, 0)               + ISNULL(Lunch06FatGramsPerEntry, 0)              + ISNULL(Lunch07FatGramsPerEntry, 0)               + ISNULL(Lunch08FatGramsPerEntry, 0)              + ISNULL(Lunch09FatGramsPerEntry, 0)            + ISNULL(Lunch10FatGramsPerEntry, 0)                              ,
    TotalSaturatedFatGramsPerDay     = TotalSaturatedFatGramsPerDay    + ISNULL(Lunch01SaturatedFatGramsPerEntry, 0)      + ISNULL(Lunch02SaturatedFatGramsPerEntry, 0)     + ISNULL(Lunch03SaturatedFatGramsPerEntry, 0)      + ISNULL(Lunch04SaturatedFatGramsPerEntry, 0)      + ISNULL(Lunch05SaturatedFatGramsPerEntry, 0)      + ISNULL(Lunch06SaturatedFatGramsPerEntry, 0)     + ISNULL(Lunch07SaturatedFatGramsPerEntry, 0)      + ISNULL(Lunch08SaturatedFatGramsPerEntry, 0)     + ISNULL(Lunch09SaturatedFatGramsPerEntry, 0)   + ISNULL(Lunch10SaturatedFatGramsPerEntry, 0)                     ,
    TotalUnsaturatedFatGramsPerDay   = TotalUnsaturatedFatGramsPerDay  + ISNULL(Lunch01UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Lunch02UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Lunch03UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Lunch04UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Lunch05UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Lunch06UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Lunch07UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Lunch08UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Lunch09UnsaturatedFatGramsPerEntry, 0) + ISNULL(Lunch10UnsaturatedFatGramsPerEntry, 0)                   ,
    TotalCholesterolGramsPerDay      = TotalCholesterolGramsPerDay     + ISNULL(Lunch01CholesterolGramsPerEntry, 0)       + ISNULL(Lunch02CholesterolGramsPerEntry, 0)      + ISNULL(Lunch03CholesterolGramsPerEntry, 0)       + ISNULL(Lunch04CholesterolGramsPerEntry, 0)       + ISNULL(Lunch05CholesterolGramsPerEntry, 0)       + ISNULL(Lunch06CholesterolGramsPerEntry, 0)      + ISNULL(Lunch07CholesterolGramsPerEntry, 0)       + ISNULL(Lunch08CholesterolGramsPerEntry, 0)      + ISNULL(Lunch09CholesterolGramsPerEntry, 0)    + ISNULL(Lunch10CholesterolGramsPerEntry, 0)                      ,
    TotalTransFatGramsPerDay         = TotalTransFatGramsPerDay        + ISNULL(Lunch01TransFatGramsPerEntry, 0)          + ISNULL(Lunch02TransFatGramsPerEntry, 0)         + ISNULL(Lunch03TransFatGramsPerEntry, 0)          + ISNULL(Lunch04TransFatGramsPerEntry, 0)          + ISNULL(Lunch05TransFatGramsPerEntry, 0)          + ISNULL(Lunch06TransFatGramsPerEntry, 0)         + ISNULL(Lunch07TransFatGramsPerEntry, 0)          + ISNULL(Lunch08TransFatGramsPerEntry, 0)         + ISNULL(Lunch09TransFatGramsPerEntry, 0)       + ISNULL(Lunch10TransFatGramsPerEntry, 0)                         ,
    TotalDietaryFibreGramsPerDay     = TotalDietaryFibreGramsPerDay    + ISNULL(Lunch01DietaryFibreGramsPerEntry, 0)      + ISNULL(Lunch02DietaryFibreGramsPerEntry, 0)     + ISNULL(Lunch03DietaryFibreGramsPerEntry, 0)      + ISNULL(Lunch04DietaryFibreGramsPerEntry, 0)      + ISNULL(Lunch05DietaryFibreGramsPerEntry, 0)      + ISNULL(Lunch06DietaryFibreGramsPerEntry, 0)     + ISNULL(Lunch07DietaryFibreGramsPerEntry, 0)      + ISNULL(Lunch08DietaryFibreGramsPerEntry, 0)     + ISNULL(Lunch09DietaryFibreGramsPerEntry, 0)   + ISNULL(Lunch10DietaryFibreGramsPerEntry, 0)                     ,
    TotalSolubleFibreGramsPerDay     = TotalSolubleFibreGramsPerDay    + ISNULL(Lunch01SolubleFibreGramsPerEntry, 0)      + ISNULL(Lunch02SolubleFibreGramsPerEntry, 0)     + ISNULL(Lunch03SolubleFibreGramsPerEntry, 0)      + ISNULL(Lunch04SolubleFibreGramsPerEntry, 0)      + ISNULL(Lunch05SolubleFibreGramsPerEntry, 0)      + ISNULL(Lunch06SolubleFibreGramsPerEntry, 0)     + ISNULL(Lunch07SolubleFibreGramsPerEntry, 0)      + ISNULL(Lunch08SolubleFibreGramsPerEntry, 0)     + ISNULL(Lunch09SolubleFibreGramsPerEntry, 0)   + ISNULL(Lunch10SolubleFibreGramsPerEntry, 0)                     ,
    TotalInsolubleFibreGramsPerDay   = TotalInsolubleFibreGramsPerDay  + ISNULL(Lunch01InsolubleFibreGramsPerEntry, 0)    + ISNULL(Lunch02InsolubleFibreGramsPerEntry, 0)   + ISNULL(Lunch03InsolubleFibreGramsPerEntry, 0)    + ISNULL(Lunch04InsolubleFibreGramsPerEntry, 0)    + ISNULL(Lunch05InsolubleFibreGramsPerEntry, 0)    + ISNULL(Lunch06InsolubleFibreGramsPerEntry, 0)   + ISNULL(Lunch07InsolubleFibreGramsPerEntry, 0)    + ISNULL(Lunch08InsolubleFibreGramsPerEntry, 0)   + ISNULL(Lunch09InsolubleFibreGramsPerEntry, 0) + ISNULL(Lunch10InsolubleFibreGramsPerEntry, 0)                   ,
    TotalSodiumGramsPerDay           = TotalSodiumGramsPerDay          + ISNULL(Lunch01SodiumGramsPerEntry, 0)            + ISNULL(Lunch02SodiumGramsPerEntry, 0)           + ISNULL(Lunch03SodiumGramsPerEntry, 0)            + ISNULL(Lunch04SodiumGramsPerEntry, 0)            + ISNULL(Lunch05SodiumGramsPerEntry, 0)            + ISNULL(Lunch06SodiumGramsPerEntry, 0)           + ISNULL(Lunch07SodiumGramsPerEntry, 0)            + ISNULL(Lunch08SodiumGramsPerEntry, 0)           + ISNULL(Lunch09SodiumGramsPerEntry, 0)         + ISNULL(Lunch10SodiumGramsPerEntry, 0)                           ,
    TotalAlcoholGramsPerDay          = TotalAlcoholGramsPerDay         + ISNULL(Lunch01AlcoholGramsPerEntry, 0)           + ISNULL(Lunch02AlcoholGramsPerEntry, 0)          + ISNULL(Lunch03AlcoholGramsPerEntry, 0)           + ISNULL(Lunch04AlcoholGramsPerEntry, 0)           + ISNULL(Lunch05AlcoholGramsPerEntry, 0)           + ISNULL(Lunch06AlcoholGramsPerEntry, 0)          + ISNULL(Lunch07AlcoholGramsPerEntry, 0)           + ISNULL(Lunch08AlcoholGramsPerEntry, 0)          + ISNULL(Lunch09AlcoholGramsPerEntry, 0)        + ISNULL(Lunch10AlcoholGramsPerEntry, 0)                           
  WHERE
    PersonGUID = @PersonGUID AND DayDate = @DayDate

  UPDATE diary.day SET 
    TotalEnergyKiloJoulesPerDay      = TotalEnergyKiloJoulesPerDay     + ISNULL(Dinner01EnergyKiloJoulesPerEntry, 0)       + ISNULL(Dinner02EnergyKiloJoulesPerEntry, 0)      + ISNULL(Dinner03EnergyKiloJoulesPerEntry, 0)       + ISNULL(Dinner04EnergyKiloJoulesPerEntry, 0)       + ISNULL(Dinner05EnergyKiloJoulesPerEntry, 0)       + ISNULL(Dinner06EnergyKiloJoulesPerEntry, 0)      + ISNULL(Dinner07EnergyKiloJoulesPerEntry, 0)       + ISNULL(Dinner08EnergyKiloJoulesPerEntry, 0)      + ISNULL(Dinner09EnergyKiloJoulesPerEntry, 0)    + ISNULL(Dinner10EnergyKiloJoulesPerEntry, 0)                      ,       
    TotalProteinGramsPerDay          = TotalProteinGramsPerDay         + ISNULL(Dinner01ProteinGramsPerEntry, 0)           + ISNULL(Dinner02ProteinGramsPerEntry, 0)          + ISNULL(Dinner03ProteinGramsPerEntry, 0)           + ISNULL(Dinner04ProteinGramsPerEntry, 0)           + ISNULL(Dinner05ProteinGramsPerEntry, 0)           + ISNULL(Dinner06ProteinGramsPerEntry, 0)          + ISNULL(Dinner07ProteinGramsPerEntry, 0)           + ISNULL(Dinner08ProteinGramsPerEntry, 0)          + ISNULL(Dinner09ProteinGramsPerEntry, 0)        + ISNULL(Dinner10ProteinGramsPerEntry, 0)                          ,
    TotalCarbohydrateGramsPerDay     = TotalCarbohydrateGramsPerDay    + ISNULL(Dinner01CarbohydrateGramsPerEntry, 0)      + ISNULL(Dinner02CarbohydrateGramsPerEntry, 0)     + ISNULL(Dinner03CarbohydrateGramsPerEntry, 0)      + ISNULL(Dinner04CarbohydrateGramsPerEntry, 0)      + ISNULL(Dinner05CarbohydrateGramsPerEntry, 0)      + ISNULL(Dinner06CarbohydrateGramsPerEntry, 0)     + ISNULL(Dinner07CarbohydrateGramsPerEntry, 0)      + ISNULL(Dinner08CarbohydrateGramsPerEntry, 0)     + ISNULL(Dinner09CarbohydrateGramsPerEntry, 0)   + ISNULL(Dinner10CarbohydrateGramsPerEntry, 0)                     ,
    TotalSugarGramsPerDay            = TotalSugarGramsPerDay           + ISNULL(Dinner01SugarGramsPerEntry, 0)             + ISNULL(Dinner02SugarGramsPerEntry, 0)            + ISNULL(Dinner03SugarGramsPerEntry, 0)             + ISNULL(Dinner04SugarGramsPerEntry, 0)             + ISNULL(Dinner05SugarGramsPerEntry, 0)             + ISNULL(Dinner06SugarGramsPerEntry, 0)            + ISNULL(Dinner07SugarGramsPerEntry, 0)             + ISNULL(Dinner08SugarGramsPerEntry, 0)            + ISNULL(Dinner09SugarGramsPerEntry, 0)          + ISNULL(Dinner10SugarGramsPerEntry, 0)                            ,
    TotalStarchGramsPerDay           = TotalStarchGramsPerDay          + ISNULL(Dinner01StarchGramsPerEntry, 0)            + ISNULL(Dinner02StarchGramsPerEntry, 0)           + ISNULL(Dinner03StarchGramsPerEntry, 0)            + ISNULL(Dinner04StarchGramsPerEntry, 0)            + ISNULL(Dinner05StarchGramsPerEntry, 0)            + ISNULL(Dinner06StarchGramsPerEntry, 0)           + ISNULL(Dinner07StarchGramsPerEntry, 0)            + ISNULL(Dinner08StarchGramsPerEntry, 0)           + ISNULL(Dinner09StarchGramsPerEntry, 0)         + ISNULL(Dinner10StarchGramsPerEntry, 0)                           ,
    TotalFatGramsPerDay              = TotalFatGramsPerDay             + ISNULL(Dinner01FatGramsPerEntry, 0)               + ISNULL(Dinner02FatGramsPerEntry, 0)              + ISNULL(Dinner03FatGramsPerEntry, 0)               + ISNULL(Dinner04FatGramsPerEntry, 0)               + ISNULL(Dinner05FatGramsPerEntry, 0)               + ISNULL(Dinner06FatGramsPerEntry, 0)              + ISNULL(Dinner07FatGramsPerEntry, 0)               + ISNULL(Dinner08FatGramsPerEntry, 0)              + ISNULL(Dinner09FatGramsPerEntry, 0)            + ISNULL(Dinner10FatGramsPerEntry, 0)                              ,
    TotalSaturatedFatGramsPerDay     = TotalSaturatedFatGramsPerDay    + ISNULL(Dinner01SaturatedFatGramsPerEntry, 0)      + ISNULL(Dinner02SaturatedFatGramsPerEntry, 0)     + ISNULL(Dinner03SaturatedFatGramsPerEntry, 0)      + ISNULL(Dinner04SaturatedFatGramsPerEntry, 0)      + ISNULL(Dinner05SaturatedFatGramsPerEntry, 0)      + ISNULL(Dinner06SaturatedFatGramsPerEntry, 0)     + ISNULL(Dinner07SaturatedFatGramsPerEntry, 0)      + ISNULL(Dinner08SaturatedFatGramsPerEntry, 0)     + ISNULL(Dinner09SaturatedFatGramsPerEntry, 0)   + ISNULL(Dinner10SaturatedFatGramsPerEntry, 0)                     ,
    TotalUnsaturatedFatGramsPerDay   = TotalUnsaturatedFatGramsPerDay  + ISNULL(Dinner01UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Dinner02UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Dinner03UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Dinner04UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Dinner05UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Dinner06UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Dinner07UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Dinner08UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Dinner09UnsaturatedFatGramsPerEntry, 0) + ISNULL(Dinner10UnsaturatedFatGramsPerEntry, 0)                   ,
    TotalCholesterolGramsPerDay      = TotalCholesterolGramsPerDay     + ISNULL(Dinner01CholesterolGramsPerEntry, 0)       + ISNULL(Dinner02CholesterolGramsPerEntry, 0)      + ISNULL(Dinner03CholesterolGramsPerEntry, 0)       + ISNULL(Dinner04CholesterolGramsPerEntry, 0)       + ISNULL(Dinner05CholesterolGramsPerEntry, 0)       + ISNULL(Dinner06CholesterolGramsPerEntry, 0)      + ISNULL(Dinner07CholesterolGramsPerEntry, 0)       + ISNULL(Dinner08CholesterolGramsPerEntry, 0)      + ISNULL(Dinner09CholesterolGramsPerEntry, 0)    + ISNULL(Dinner10CholesterolGramsPerEntry, 0)                      ,
    TotalTransFatGramsPerDay         = TotalTransFatGramsPerDay        + ISNULL(Dinner01TransFatGramsPerEntry, 0)          + ISNULL(Dinner02TransFatGramsPerEntry, 0)         + ISNULL(Dinner03TransFatGramsPerEntry, 0)          + ISNULL(Dinner04TransFatGramsPerEntry, 0)          + ISNULL(Dinner05TransFatGramsPerEntry, 0)          + ISNULL(Dinner06TransFatGramsPerEntry, 0)         + ISNULL(Dinner07TransFatGramsPerEntry, 0)          + ISNULL(Dinner08TransFatGramsPerEntry, 0)         + ISNULL(Dinner09TransFatGramsPerEntry, 0)       + ISNULL(Dinner10TransFatGramsPerEntry, 0)                         ,
    TotalDietaryFibreGramsPerDay     = TotalDietaryFibreGramsPerDay    + ISNULL(Dinner01DietaryFibreGramsPerEntry, 0)      + ISNULL(Dinner02DietaryFibreGramsPerEntry, 0)     + ISNULL(Dinner03DietaryFibreGramsPerEntry, 0)      + ISNULL(Dinner04DietaryFibreGramsPerEntry, 0)      + ISNULL(Dinner05DietaryFibreGramsPerEntry, 0)      + ISNULL(Dinner06DietaryFibreGramsPerEntry, 0)     + ISNULL(Dinner07DietaryFibreGramsPerEntry, 0)      + ISNULL(Dinner08DietaryFibreGramsPerEntry, 0)     + ISNULL(Dinner09DietaryFibreGramsPerEntry, 0)   + ISNULL(Dinner10DietaryFibreGramsPerEntry, 0)                     ,
    TotalSolubleFibreGramsPerDay     = TotalSolubleFibreGramsPerDay    + ISNULL(Dinner01SolubleFibreGramsPerEntry, 0)      + ISNULL(Dinner02SolubleFibreGramsPerEntry, 0)     + ISNULL(Dinner03SolubleFibreGramsPerEntry, 0)      + ISNULL(Dinner04SolubleFibreGramsPerEntry, 0)      + ISNULL(Dinner05SolubleFibreGramsPerEntry, 0)      + ISNULL(Dinner06SolubleFibreGramsPerEntry, 0)     + ISNULL(Dinner07SolubleFibreGramsPerEntry, 0)      + ISNULL(Dinner08SolubleFibreGramsPerEntry, 0)     + ISNULL(Dinner09SolubleFibreGramsPerEntry, 0)   + ISNULL(Dinner10SolubleFibreGramsPerEntry, 0)                     ,
    TotalInsolubleFibreGramsPerDay   = TotalInsolubleFibreGramsPerDay  + ISNULL(Dinner01InsolubleFibreGramsPerEntry, 0)    + ISNULL(Dinner02InsolubleFibreGramsPerEntry, 0)   + ISNULL(Dinner03InsolubleFibreGramsPerEntry, 0)    + ISNULL(Dinner04InsolubleFibreGramsPerEntry, 0)    + ISNULL(Dinner05InsolubleFibreGramsPerEntry, 0)    + ISNULL(Dinner06InsolubleFibreGramsPerEntry, 0)   + ISNULL(Dinner07InsolubleFibreGramsPerEntry, 0)    + ISNULL(Dinner08InsolubleFibreGramsPerEntry, 0)   + ISNULL(Dinner09InsolubleFibreGramsPerEntry, 0) + ISNULL(Dinner10InsolubleFibreGramsPerEntry, 0)                   ,
    TotalSodiumGramsPerDay           = TotalSodiumGramsPerDay          + ISNULL(Dinner01SodiumGramsPerEntry, 0)            + ISNULL(Dinner02SodiumGramsPerEntry, 0)           + ISNULL(Dinner03SodiumGramsPerEntry, 0)            + ISNULL(Dinner04SodiumGramsPerEntry, 0)            + ISNULL(Dinner05SodiumGramsPerEntry, 0)            + ISNULL(Dinner06SodiumGramsPerEntry, 0)           + ISNULL(Dinner07SodiumGramsPerEntry, 0)            + ISNULL(Dinner08SodiumGramsPerEntry, 0)           + ISNULL(Dinner09SodiumGramsPerEntry, 0)         + ISNULL(Dinner10SodiumGramsPerEntry, 0)                           ,
    TotalAlcoholGramsPerDay          = TotalAlcoholGramsPerDay         + ISNULL(Dinner01AlcoholGramsPerEntry, 0)           + ISNULL(Dinner02AlcoholGramsPerEntry, 0)          + ISNULL(Dinner03AlcoholGramsPerEntry, 0)           + ISNULL(Dinner04AlcoholGramsPerEntry, 0)           + ISNULL(Dinner05AlcoholGramsPerEntry, 0)           + ISNULL(Dinner06AlcoholGramsPerEntry, 0)          + ISNULL(Dinner07AlcoholGramsPerEntry, 0)           + ISNULL(Dinner08AlcoholGramsPerEntry, 0)          + ISNULL(Dinner09AlcoholGramsPerEntry, 0)        + ISNULL(Dinner10AlcoholGramsPerEntry, 0)                           
  WHERE
    PersonGUID = @PersonGUID AND DayDate = @DayDate

  UPDATE diary.day SET 
    TotalEnergyKiloJoulesPerDay      = TotalEnergyKiloJoulesPerDay     + ISNULL(Snacks01EnergyKiloJoulesPerEntry, 0)       + ISNULL(Snacks02EnergyKiloJoulesPerEntry, 0)      + ISNULL(Snacks03EnergyKiloJoulesPerEntry, 0)       + ISNULL(Snacks04EnergyKiloJoulesPerEntry, 0)       + ISNULL(Snacks05EnergyKiloJoulesPerEntry, 0)       + ISNULL(Snacks06EnergyKiloJoulesPerEntry, 0)      + ISNULL(Snacks07EnergyKiloJoulesPerEntry, 0)       + ISNULL(Snacks08EnergyKiloJoulesPerEntry, 0)      + ISNULL(Snacks09EnergyKiloJoulesPerEntry, 0)    + ISNULL(Snacks10EnergyKiloJoulesPerEntry, 0)                      ,       
    TotalProteinGramsPerDay          = TotalProteinGramsPerDay         + ISNULL(Snacks01ProteinGramsPerEntry, 0)           + ISNULL(Snacks02ProteinGramsPerEntry, 0)          + ISNULL(Snacks03ProteinGramsPerEntry, 0)           + ISNULL(Snacks04ProteinGramsPerEntry, 0)           + ISNULL(Snacks05ProteinGramsPerEntry, 0)           + ISNULL(Snacks06ProteinGramsPerEntry, 0)          + ISNULL(Snacks07ProteinGramsPerEntry, 0)           + ISNULL(Snacks08ProteinGramsPerEntry, 0)          + ISNULL(Snacks09ProteinGramsPerEntry, 0)        + ISNULL(Snacks10ProteinGramsPerEntry, 0)                          ,
    TotalCarbohydrateGramsPerDay     = TotalCarbohydrateGramsPerDay    + ISNULL(Snacks01CarbohydrateGramsPerEntry, 0)      + ISNULL(Snacks02CarbohydrateGramsPerEntry, 0)     + ISNULL(Snacks03CarbohydrateGramsPerEntry, 0)      + ISNULL(Snacks04CarbohydrateGramsPerEntry, 0)      + ISNULL(Snacks05CarbohydrateGramsPerEntry, 0)      + ISNULL(Snacks06CarbohydrateGramsPerEntry, 0)     + ISNULL(Snacks07CarbohydrateGramsPerEntry, 0)      + ISNULL(Snacks08CarbohydrateGramsPerEntry, 0)     + ISNULL(Snacks09CarbohydrateGramsPerEntry, 0)   + ISNULL(Snacks10CarbohydrateGramsPerEntry, 0)                     ,
    TotalSugarGramsPerDay            = TotalSugarGramsPerDay           + ISNULL(Snacks01SugarGramsPerEntry, 0)             + ISNULL(Snacks02SugarGramsPerEntry, 0)            + ISNULL(Snacks03SugarGramsPerEntry, 0)             + ISNULL(Snacks04SugarGramsPerEntry, 0)             + ISNULL(Snacks05SugarGramsPerEntry, 0)             + ISNULL(Snacks06SugarGramsPerEntry, 0)            + ISNULL(Snacks07SugarGramsPerEntry, 0)             + ISNULL(Snacks08SugarGramsPerEntry, 0)            + ISNULL(Snacks09SugarGramsPerEntry, 0)          + ISNULL(Snacks10SugarGramsPerEntry, 0)                            ,
    TotalStarchGramsPerDay           = TotalStarchGramsPerDay          + ISNULL(Snacks01StarchGramsPerEntry, 0)            + ISNULL(Snacks02StarchGramsPerEntry, 0)           + ISNULL(Snacks03StarchGramsPerEntry, 0)            + ISNULL(Snacks04StarchGramsPerEntry, 0)            + ISNULL(Snacks05StarchGramsPerEntry, 0)            + ISNULL(Snacks06StarchGramsPerEntry, 0)           + ISNULL(Snacks07StarchGramsPerEntry, 0)            + ISNULL(Snacks08StarchGramsPerEntry, 0)           + ISNULL(Snacks09StarchGramsPerEntry, 0)         + ISNULL(Snacks10StarchGramsPerEntry, 0)                           ,
    TotalFatGramsPerDay              = TotalFatGramsPerDay             + ISNULL(Snacks01FatGramsPerEntry, 0)               + ISNULL(Snacks02FatGramsPerEntry, 0)              + ISNULL(Snacks03FatGramsPerEntry, 0)               + ISNULL(Snacks04FatGramsPerEntry, 0)               + ISNULL(Snacks05FatGramsPerEntry, 0)               + ISNULL(Snacks06FatGramsPerEntry, 0)              + ISNULL(Snacks07FatGramsPerEntry, 0)               + ISNULL(Snacks08FatGramsPerEntry, 0)              + ISNULL(Snacks09FatGramsPerEntry, 0)            + ISNULL(Snacks10FatGramsPerEntry, 0)                              ,
    TotalSaturatedFatGramsPerDay     = TotalSaturatedFatGramsPerDay    + ISNULL(Snacks01SaturatedFatGramsPerEntry, 0)      + ISNULL(Snacks02SaturatedFatGramsPerEntry, 0)     + ISNULL(Snacks03SaturatedFatGramsPerEntry, 0)      + ISNULL(Snacks04SaturatedFatGramsPerEntry, 0)      + ISNULL(Snacks05SaturatedFatGramsPerEntry, 0)      + ISNULL(Snacks06SaturatedFatGramsPerEntry, 0)     + ISNULL(Snacks07SaturatedFatGramsPerEntry, 0)      + ISNULL(Snacks08SaturatedFatGramsPerEntry, 0)     + ISNULL(Snacks09SaturatedFatGramsPerEntry, 0)   + ISNULL(Snacks10SaturatedFatGramsPerEntry, 0)                     ,
    TotalUnsaturatedFatGramsPerDay   = TotalUnsaturatedFatGramsPerDay  + ISNULL(Snacks01UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Snacks02UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Snacks03UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Snacks04UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Snacks05UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Snacks06UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Snacks07UnsaturatedFatGramsPerEntry, 0)    + ISNULL(Snacks08UnsaturatedFatGramsPerEntry, 0)   + ISNULL(Snacks09UnsaturatedFatGramsPerEntry, 0) + ISNULL(Snacks10UnsaturatedFatGramsPerEntry, 0)                   ,
    TotalCholesterolGramsPerDay      = TotalCholesterolGramsPerDay     + ISNULL(Snacks01CholesterolGramsPerEntry, 0)       + ISNULL(Snacks02CholesterolGramsPerEntry, 0)      + ISNULL(Snacks03CholesterolGramsPerEntry, 0)       + ISNULL(Snacks04CholesterolGramsPerEntry, 0)       + ISNULL(Snacks05CholesterolGramsPerEntry, 0)       + ISNULL(Snacks06CholesterolGramsPerEntry, 0)      + ISNULL(Snacks07CholesterolGramsPerEntry, 0)       + ISNULL(Snacks08CholesterolGramsPerEntry, 0)      + ISNULL(Snacks09CholesterolGramsPerEntry, 0)    + ISNULL(Snacks10CholesterolGramsPerEntry, 0)                      ,
    TotalTransFatGramsPerDay         = TotalTransFatGramsPerDay        + ISNULL(Snacks01TransFatGramsPerEntry, 0)          + ISNULL(Snacks02TransFatGramsPerEntry, 0)         + ISNULL(Snacks03TransFatGramsPerEntry, 0)          + ISNULL(Snacks04TransFatGramsPerEntry, 0)          + ISNULL(Snacks05TransFatGramsPerEntry, 0)          + ISNULL(Snacks06TransFatGramsPerEntry, 0)         + ISNULL(Snacks07TransFatGramsPerEntry, 0)          + ISNULL(Snacks08TransFatGramsPerEntry, 0)         + ISNULL(Snacks09TransFatGramsPerEntry, 0)       + ISNULL(Snacks10TransFatGramsPerEntry, 0)                         ,
    TotalDietaryFibreGramsPerDay     = TotalDietaryFibreGramsPerDay    + ISNULL(Snacks01DietaryFibreGramsPerEntry, 0)      + ISNULL(Snacks02DietaryFibreGramsPerEntry, 0)     + ISNULL(Snacks03DietaryFibreGramsPerEntry, 0)      + ISNULL(Snacks04DietaryFibreGramsPerEntry, 0)      + ISNULL(Snacks05DietaryFibreGramsPerEntry, 0)      + ISNULL(Snacks06DietaryFibreGramsPerEntry, 0)     + ISNULL(Snacks07DietaryFibreGramsPerEntry, 0)      + ISNULL(Snacks08DietaryFibreGramsPerEntry, 0)     + ISNULL(Snacks09DietaryFibreGramsPerEntry, 0)   + ISNULL(Snacks10DietaryFibreGramsPerEntry, 0)                     ,
    TotalSolubleFibreGramsPerDay     = TotalSolubleFibreGramsPerDay    + ISNULL(Snacks01SolubleFibreGramsPerEntry, 0)      + ISNULL(Snacks02SolubleFibreGramsPerEntry, 0)     + ISNULL(Snacks03SolubleFibreGramsPerEntry, 0)      + ISNULL(Snacks04SolubleFibreGramsPerEntry, 0)      + ISNULL(Snacks05SolubleFibreGramsPerEntry, 0)      + ISNULL(Snacks06SolubleFibreGramsPerEntry, 0)     + ISNULL(Snacks07SolubleFibreGramsPerEntry, 0)      + ISNULL(Snacks08SolubleFibreGramsPerEntry, 0)     + ISNULL(Snacks09SolubleFibreGramsPerEntry, 0)   + ISNULL(Snacks10SolubleFibreGramsPerEntry, 0)                     ,
    TotalInsolubleFibreGramsPerDay   = TotalInsolubleFibreGramsPerDay  + ISNULL(Snacks01InsolubleFibreGramsPerEntry, 0)    + ISNULL(Snacks02InsolubleFibreGramsPerEntry, 0)   + ISNULL(Snacks03InsolubleFibreGramsPerEntry, 0)    + ISNULL(Snacks04InsolubleFibreGramsPerEntry, 0)    + ISNULL(Snacks05InsolubleFibreGramsPerEntry, 0)    + ISNULL(Snacks06InsolubleFibreGramsPerEntry, 0)   + ISNULL(Snacks07InsolubleFibreGramsPerEntry, 0)    + ISNULL(Snacks08InsolubleFibreGramsPerEntry, 0)   + ISNULL(Snacks09InsolubleFibreGramsPerEntry, 0) + ISNULL(Snacks10InsolubleFibreGramsPerEntry, 0)                   ,
    TotalSodiumGramsPerDay           = TotalSodiumGramsPerDay          + ISNULL(Snacks01SodiumGramsPerEntry, 0)            + ISNULL(Snacks02SodiumGramsPerEntry, 0)           + ISNULL(Snacks03SodiumGramsPerEntry, 0)            + ISNULL(Snacks04SodiumGramsPerEntry, 0)            + ISNULL(Snacks05SodiumGramsPerEntry, 0)            + ISNULL(Snacks06SodiumGramsPerEntry, 0)           + ISNULL(Snacks07SodiumGramsPerEntry, 0)            + ISNULL(Snacks08SodiumGramsPerEntry, 0)           + ISNULL(Snacks09SodiumGramsPerEntry, 0)         + ISNULL(Snacks10SodiumGramsPerEntry, 0)                           ,
    TotalAlcoholGramsPerDay          = TotalAlcoholGramsPerDay         + ISNULL(Snacks01AlcoholGramsPerEntry, 0)           + ISNULL(Snacks02AlcoholGramsPerEntry, 0)          + ISNULL(Snacks03AlcoholGramsPerEntry, 0)           + ISNULL(Snacks04AlcoholGramsPerEntry, 0)           + ISNULL(Snacks05AlcoholGramsPerEntry, 0)           + ISNULL(Snacks06AlcoholGramsPerEntry, 0)          + ISNULL(Snacks07AlcoholGramsPerEntry, 0)           + ISNULL(Snacks08AlcoholGramsPerEntry, 0)          + ISNULL(Snacks09AlcoholGramsPerEntry, 0)        + ISNULL(Snacks10AlcoholGramsPerEntry, 0)                           
  WHERE
    PersonGUID = @PersonGUID AND DayDate = @DayDate

RETURN @@rowcount
go

REVOKE EXECUTE ON diary.ProcessCalculateDay TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForExistingUser 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
-- EXECUTE diary.GetDays 'F5CF71AA-4EC0-4D47-B33B-8E228212F343',  365
-----------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE diary.GetDays
(
   @SessionGUID     uniqueidentifier,
   @DayCount        integer = 30,
   @SkipDays        integer = 0  
)
AS
--
DECLARE @PersonGUID uniqueidentifier
SELECT  @PersonGUID = PersonGUID FROM security.Session WHERE SessionGUID = @SessionGUID AND IsActive = 1 AND SessionExpiresUTC > GETUTCDATE()     
--
DECLARE @EndDate   date = dateadd(day, -1 * abs(@SkipDays), getutcdate());
DECLARE @StartDate date = dateadd(day, -1 * abs(@DayCount), @EndDate    );
--
DECLARE @RANGE TABLE (dayDate date);
--
WITH DATE_RANGE AS (
    SELECT @StartDate AS dayDate
    UNION ALL
    SELECT DATEADD(dd, 1, dayDate)
    FROM   DATE_RANGE R
    WHERE  DATEADD(dd, 1, dayDate) <= @EndDate)    
INSERT INTO @RANGE (dayDate)
    SELECT  R.dayDate
    FROM    DATE_RANGE R
    OPTION (MAXRECURSION 0)
--
IF @PersonGUID IS NOT NULL BEGIN
  --
  SELECT 
	    CONVERT(varchar(10), R.DayDate, 127)                  'dayDate',
	    D.EditCount                                           'editCount' 
  FROM
      @RANGE R
  LEFT OUTER JOIN
      diary.Day D WITH (INDEX(DaySKPersonDayEdit))   ON R.dayDate = D.dayDate AND D.PersonGUID = @PersonGUID
  --WHERE
  --    D.EditCount IS NOT NULL
  ORDER BY
    DayDate DESC  
END

RETURN @@rowcount

go

GRANT EXECUTE ON diary.GetDays TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForAnonymousUser '127.0.0.1'
-- security.GetAuthorizationForExistingUser 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
-- EXECUTE diary.GetDetails '144F8D8A-6947-481F-BEA3-3BFD6C77FA5A', '2016-06-11, 2016-06-10, 2016-06-09, 2016-06-08, 2016-06-07, 2016-06-06, 2016-06-05, 2016-06-04, 2016-06-03, 2016-06-02, 2016-06-01, 2016-05-31'
-- EXECUTE diary.GetDetails 'F5CF71AA-4EC0-4D47-B33B-8E228212F343', '2016-06-11' 
-- EXECUTE diary.GetDetails 'F5CF71AA-4EC0-4D47-B33B-8E228212F343', '2016-06-11, 2016-06-10' 
-----------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE diary.GetDetails
(
   @SessionGUID     uniqueidentifier,
   @DayDates        varchar(max) 
)
AS
--
DECLARE @PersonGUID uniqueidentifier
SELECT  @PersonGUID = PersonGUID FROM security.Session WHERE SessionGUID = @SessionGUID AND IsActive = 1 AND SessionExpiresUTC > GETUTCDATE()
--
DECLARE @DATES TABLE 
(
  dayDate date
)
--
IF @PersonGUID IS NOT NULL BEGIN

   INSERT INTO @DATES
      SELECT 
       cast(item as date) 
      FROM 
        dbo.ListToTable(@DayDates, ',')
   -- 
   INSERT INTO diary.Day (PersonGUID, DayDate, EditCount) 
     SELECT 
       @PersonGUID,
       dayDate,
       0
     FROM
       @DATES
     WHERE
       dayDate NOT IN (
         SELECT  
           dayDate
        FROM
            diary.Day
          WHERE
            PersonGUID = @PersonGUID          
       )
  --
  SELECT
	  CONVERT(varchar(10), DayDate, 127)                  'dayDate',
	  EditCount                                           'editCount',
	  ISNULL(TotalEnergyKiloJoulesPerDay, 0)              'totalEnergyKiloJoulesPerDay',
	  ISNULL(TotalProteinGramsPerDay, 0)                  'totalProteinGramsPerDay',
	  ISNULL(TotalCarbohydrateGramsPerDay, 0)             'totalCarbohydrateGramsPerDay',
	  ISNULL(TotalSugarGramsPerDay, 0)                    'totalSugarGramsPerDay',
	  ISNULL(TotalStarchGramsPerDay, 0)                   'totalStarchGramsPerDay',
	  ISNULL(TotalFatGramsPerDay, 0)                      'totalFatGramsPerDay',
	  ISNULL(TotalSaturatedFatGramsPerDay, 0)             'totalSaturatedFatGramsPerDay',
	  ISNULL(TotalUnsaturatedFatGramsPerDay, 0)           'totalUnsaturatedFatGramsPerDay',
	  ISNULL(TotalCholesterolGramsPerDay, 0)              'totalCholesterolGramsPerDay',
	  ISNULL(TotalTransFatGramsPerDay, 0)                 'totalTransFatGramsPerDay',
	  ISNULL(TotalSodiumGramsPerDay, 0)                   'totalSodiumGramsPerDay',
	  ISNULL(TotalDietaryFibreGramsPerDay, 0)             'totalDietaryFibreGramsPerDay',
	  ISNULL(TotalSolubleFibreGramsPerDay, 0)             'totalSolubleFibreGramsPerDay',
	  ISNULL(TotalInsolubleFibreGramsPerDay, 0)           'totalInsolubleFibreGramsPerDay',
	  ISNULL(TotalAlcoholGramsPerDay, 0)                  'totalAlcoholGramsPerDay',
	  ISNULL(TotalDurationHoursPerDay, 0)                 'totalDurationHoursPerDay',
	  ISNULL(TotalDistanceKilometersPerDay, 0)            'totalDistanceKilometersPerDay',
	  ISNULL(TotalEnergyKilojoules, 0)                    'totalEnergyKilojoules',
	  AverageWeightKilograms                              'averageWeightKilograms',
	  AverageBloodPressureMillimetersofMercury            'averageBloodPressureMillimetersofMercury',
	  AverageHeartRateBeatsPerMinuteAverage               'averageHeartRateBeatsPerMinuteAverage',
	    
    MeasurementWaistCentimeters                         'measurementWaistCentimeters',
	  MeasurementThighCentimeters                         'measurementThighCentimeters',
	  MeasurementChestCentimeters                         'measurementChestCentimeters',
	  MeasurementHipsCentimeters                          'measurementHipsCentimeters',
	  MeasurementBicepCentimeters                         'measurementBicepCentimeters',
	    
          Breakfast01FoodDescription                                               'breakfast01FoodDescription',
	        Breakfast01AmountDescription                                             'breakfast01AmountDescription',
	  cast(Breakfast01EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast01EnergyKiloJoulesPerEntry',
	  cast(Breakfast01ProteinGramsPerEntry         as decimal(8,1))                 'breakfast01ProteinGramsPerEntry',
	  cast(Breakfast01CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast01CarbohydrateGramsPerEntry',
	  cast(Breakfast01SugarGramsPerEntry           as decimal(8,1))                 'breakfast01SugarGramsPerEntry',
	  cast(Breakfast01StarchGramsPerEntry          as decimal(8,1))                 'breakfast01StarchGramsPerEntry',
	  cast(Breakfast01FatGramsPerEntry             as decimal(8,1))                 'breakfast01FatGramsPerEntry',
	  cast(Breakfast01SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast01SaturatedFatGramsPerEntry',
	  cast(Breakfast01UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast01UnsaturatedFatGramsPerEntry',
	  cast(Breakfast01CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast01CholesterolGramsPerEntry',
	  cast(Breakfast01TransFatGramsPerEntry        as decimal(8,1))                 'breakfast01TransFatGramsPerEntry',
	  cast(Breakfast01DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast01DietaryFibreGramsPerEntry',
	  cast(Breakfast01SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast01SolubleFibreGramsPerEntry',
	  cast(Breakfast01InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast01InsolubleFibreGramsPerEntry',
	  cast(Breakfast01SodiumGramsPerEntry          as decimal(8,2))                 'breakfast01SodiumGramsPerEntry',
	  cast(Breakfast01AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast01AlcoholGramsPerEntry',
	        Breakfast02FoodDescription                                               'breakfast02FoodDescription',
	        Breakfast02AmountDescription                                             'breakfast02AmountDescription',
	  cast(Breakfast02EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast02EnergyKiloJoulesPerEntry',
	  cast(Breakfast02ProteinGramsPerEntry         as decimal(8,1))                 'breakfast02ProteinGramsPerEntry',
	  cast(Breakfast02CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast02CarbohydrateGramsPerEntry',
	  cast(Breakfast02SugarGramsPerEntry           as decimal(8,1))                 'breakfast02SugarGramsPerEntry',
	  cast(Breakfast02StarchGramsPerEntry          as decimal(8,1))                 'breakfast02StarchGramsPerEntry',
	  cast(Breakfast02FatGramsPerEntry             as decimal(8,1))                 'breakfast02FatGramsPerEntry',
	  cast(Breakfast02SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast02SaturatedFatGramsPerEntry',
	  cast(Breakfast02UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast02UnsaturatedFatGramsPerEntry',
	  cast(Breakfast02CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast02CholesterolGramsPerEntry',
	  cast(Breakfast02TransFatGramsPerEntry        as decimal(8,1))                 'breakfast02TransFatGramsPerEntry',
	  cast(Breakfast02DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast02DietaryFibreGramsPerEntry',
	  cast(Breakfast02SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast02SolubleFibreGramsPerEntry',
	  cast(Breakfast02InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast02InsolubleFibreGramsPerEntry',
	  cast(Breakfast02SodiumGramsPerEntry          as decimal(8,2))                 'breakfast02SodiumGramsPerEntry',
	  cast(Breakfast02AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast02AlcoholGramsPerEntry',
	        Breakfast03FoodDescription                                               'breakfast03FoodDescription',
	        Breakfast03AmountDescription                                             'breakfast03AmountDescription',
	  cast(Breakfast03EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast03EnergyKiloJoulesPerEntry',
	  cast(Breakfast03ProteinGramsPerEntry         as decimal(8,1))                 'breakfast03ProteinGramsPerEntry',
	  cast(Breakfast03CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast03CarbohydrateGramsPerEntry',
	  cast(Breakfast03SugarGramsPerEntry           as decimal(8,1))                 'breakfast03SugarGramsPerEntry',
	  cast(Breakfast03StarchGramsPerEntry          as decimal(8,1))                 'breakfast03StarchGramsPerEntry',
	  cast(Breakfast03FatGramsPerEntry             as decimal(8,1))                 'breakfast03FatGramsPerEntry',
	  cast(Breakfast03SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast03SaturatedFatGramsPerEntry',
	  cast(Breakfast03UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast03UnsaturatedFatGramsPerEntry',
	  cast(Breakfast03CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast03CholesterolGramsPerEntry',
	  cast(Breakfast03TransFatGramsPerEntry        as decimal(8,1))                 'breakfast03TransFatGramsPerEntry',
	  cast(Breakfast03DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast03DietaryFibreGramsPerEntry',
	  cast(Breakfast03SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast03SolubleFibreGramsPerEntry',
	  cast(Breakfast03InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast03InsolubleFibreGramsPerEntry',
	  cast(Breakfast03SodiumGramsPerEntry          as decimal(8,2))                 'breakfast03SodiumGramsPerEntry',
	  cast(Breakfast03AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast03AlcoholGramsPerEntry',
	        Breakfast04FoodDescription                                               'breakfast04FoodDescription',
	        Breakfast04AmountDescription                                             'breakfast04AmountDescription',
	  cast(Breakfast04EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast04EnergyKiloJoulesPerEntry',
	  cast(Breakfast04ProteinGramsPerEntry         as decimal(8,1))                 'breakfast04ProteinGramsPerEntry',
	  cast(Breakfast04CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast04CarbohydrateGramsPerEntry',
	  cast(Breakfast04SugarGramsPerEntry           as decimal(8,1))                 'breakfast04SugarGramsPerEntry',
	  cast(Breakfast04StarchGramsPerEntry          as decimal(8,1))                 'breakfast04StarchGramsPerEntry',
	  cast(Breakfast04FatGramsPerEntry             as decimal(8,1))                 'breakfast04FatGramsPerEntry',
	  cast(Breakfast04SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast04SaturatedFatGramsPerEntry',
	  cast(Breakfast04UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast04UnsaturatedFatGramsPerEntry',
	  cast(Breakfast04CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast04CholesterolGramsPerEntry',
	  cast(Breakfast04TransFatGramsPerEntry        as decimal(8,1))                 'breakfast04TransFatGramsPerEntry',
	  cast(Breakfast04DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast04DietaryFibreGramsPerEntry',
	  cast(Breakfast04SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast04SolubleFibreGramsPerEntry',
	  cast(Breakfast04InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast04InsolubleFibreGramsPerEntry',
	  cast(Breakfast04SodiumGramsPerEntry          as decimal(8,2))                 'breakfast04SodiumGramsPerEntry',
	  cast(Breakfast04AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast04AlcoholGramsPerEntry',
	        Breakfast05FoodDescription                                               'breakfast05FoodDescription',
	        Breakfast05AmountDescription                                             'breakfast05AmountDescription',
	  cast(Breakfast05EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast05EnergyKiloJoulesPerEntry',
	  cast(Breakfast05ProteinGramsPerEntry         as decimal(8,1))                 'breakfast05ProteinGramsPerEntry',
	  cast(Breakfast05CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast05CarbohydrateGramsPerEntry',
	  cast(Breakfast05SugarGramsPerEntry           as decimal(8,1))                 'breakfast05SugarGramsPerEntry',
	  cast(Breakfast05StarchGramsPerEntry          as decimal(8,1))                 'breakfast05StarchGramsPerEntry',
	  cast(Breakfast05FatGramsPerEntry             as decimal(8,1))                 'breakfast05FatGramsPerEntry',
	  cast(Breakfast05SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast05SaturatedFatGramsPerEntry',
	  cast(Breakfast05UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast05UnsaturatedFatGramsPerEntry',
	  cast(Breakfast05CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast05CholesterolGramsPerEntry',
	  cast(Breakfast05TransFatGramsPerEntry        as decimal(8,1))                 'breakfast05TransFatGramsPerEntry',
	  cast(Breakfast05DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast05DietaryFibreGramsPerEntry',
	  cast(Breakfast05SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast05SolubleFibreGramsPerEntry',
	  cast(Breakfast05InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast05InsolubleFibreGramsPerEntry',
	  cast(Breakfast05SodiumGramsPerEntry          as decimal(8,2))                 'breakfast05SodiumGramsPerEntry',
	  cast(Breakfast05AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast05AlcoholGramsPerEntry',
	        Breakfast06FoodDescription                                               'breakfast06FoodDescription',
	        Breakfast06AmountDescription                                             'breakfast06AmountDescription',
	  cast(Breakfast06EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast06EnergyKiloJoulesPerEntry',
	  cast(Breakfast06ProteinGramsPerEntry         as decimal(8,1))                 'breakfast06ProteinGramsPerEntry',
	  cast(Breakfast06CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast06CarbohydrateGramsPerEntry',
	  cast(Breakfast06SugarGramsPerEntry           as decimal(8,1))                 'breakfast06SugarGramsPerEntry',
	  cast(Breakfast06StarchGramsPerEntry          as decimal(8,1))                 'breakfast06StarchGramsPerEntry',
	  cast(Breakfast06FatGramsPerEntry             as decimal(8,1))                 'breakfast06FatGramsPerEntry',
	  cast(Breakfast06SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast06SaturatedFatGramsPerEntry',
	  cast(Breakfast06UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast06UnsaturatedFatGramsPerEntry',
	  cast(Breakfast06CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast06CholesterolGramsPerEntry',
	  cast(Breakfast06TransFatGramsPerEntry        as decimal(8,1))                 'breakfast06TransFatGramsPerEntry',
	  cast(Breakfast06DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast06DietaryFibreGramsPerEntry',
	  cast(Breakfast06SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast06SolubleFibreGramsPerEntry',
	  cast(Breakfast06InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast06InsolubleFibreGramsPerEntry',
	  cast(Breakfast06SodiumGramsPerEntry          as decimal(8,2))                 'breakfast06SodiumGramsPerEntry',
	  cast(Breakfast06AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast06AlcoholGramsPerEntry',
	        Breakfast07FoodDescription                                               'breakfast07FoodDescription',
	        Breakfast07AmountDescription                                             'breakfast07AmountDescription',
	  cast(Breakfast07EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast07EnergyKiloJoulesPerEntry',
	  cast(Breakfast07ProteinGramsPerEntry         as decimal(8,1))                 'breakfast07ProteinGramsPerEntry',
	  cast(Breakfast07CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast07CarbohydrateGramsPerEntry',
	  cast(Breakfast07SugarGramsPerEntry           as decimal(8,1))                 'breakfast07SugarGramsPerEntry',
	  cast(Breakfast07StarchGramsPerEntry          as decimal(8,1))                 'breakfast07StarchGramsPerEntry',
	  cast(Breakfast07FatGramsPerEntry             as decimal(8,1))                 'breakfast07FatGramsPerEntry',
	  cast(Breakfast07SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast07SaturatedFatGramsPerEntry',
	  cast(Breakfast07UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast07UnsaturatedFatGramsPerEntry',
	  cast(Breakfast07CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast07CholesterolGramsPerEntry',
	  cast(Breakfast07TransFatGramsPerEntry        as decimal(8,1))                 'breakfast07TransFatGramsPerEntry',
	  cast(Breakfast07DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast07DietaryFibreGramsPerEntry',
	  cast(Breakfast07SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast07SolubleFibreGramsPerEntry',
	  cast(Breakfast07InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast07InsolubleFibreGramsPerEntry',
	  cast(Breakfast07SodiumGramsPerEntry          as decimal(8,2))                 'breakfast07SodiumGramsPerEntry',
	  cast(Breakfast07AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast07AlcoholGramsPerEntry',
	        Breakfast08FoodDescription                                               'breakfast08FoodDescription',
	        Breakfast08AmountDescription                                             'breakfast08AmountDescription',
	  cast(Breakfast08EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast08EnergyKiloJoulesPerEntry',
	  cast(Breakfast08ProteinGramsPerEntry         as decimal(8,1))                 'breakfast08ProteinGramsPerEntry',
	  cast(Breakfast08CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast08CarbohydrateGramsPerEntry',
	  cast(Breakfast08SugarGramsPerEntry           as decimal(8,1))                 'breakfast08SugarGramsPerEntry',
	  cast(Breakfast08StarchGramsPerEntry          as decimal(8,1))                 'breakfast08StarchGramsPerEntry',
	  cast(Breakfast08FatGramsPerEntry             as decimal(8,1))                 'breakfast08FatGramsPerEntry',
	  cast(Breakfast08SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast08SaturatedFatGramsPerEntry',
	  cast(Breakfast08UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast08UnsaturatedFatGramsPerEntry',
	  cast(Breakfast08CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast08CholesterolGramsPerEntry',
	  cast(Breakfast08TransFatGramsPerEntry        as decimal(8,1))                 'breakfast08TransFatGramsPerEntry',
	  cast(Breakfast08DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast08DietaryFibreGramsPerEntry',
	  cast(Breakfast08SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast08SolubleFibreGramsPerEntry',
	  cast(Breakfast08InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast08InsolubleFibreGramsPerEntry',
	  cast(Breakfast08SodiumGramsPerEntry          as decimal(8,2))                 'breakfast08SodiumGramsPerEntry',
	  cast(Breakfast08AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast08AlcoholGramsPerEntry',
	        Breakfast09FoodDescription                                               'breakfast09FoodDescription',
	        Breakfast09AmountDescription                                             'breakfast09AmountDescription',
	  cast(Breakfast09EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast09EnergyKiloJoulesPerEntry',
	  cast(Breakfast09ProteinGramsPerEntry         as decimal(8,1))                 'breakfast09ProteinGramsPerEntry',
	  cast(Breakfast09CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast09CarbohydrateGramsPerEntry',
	  cast(Breakfast09SugarGramsPerEntry           as decimal(8,1))                 'breakfast09SugarGramsPerEntry',
	  cast(Breakfast09StarchGramsPerEntry          as decimal(8,1))                 'breakfast09StarchGramsPerEntry',
	  cast(Breakfast09FatGramsPerEntry             as decimal(8,1))                 'breakfast09FatGramsPerEntry',
	  cast(Breakfast09SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast09SaturatedFatGramsPerEntry',
	  cast(Breakfast09UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast09UnsaturatedFatGramsPerEntry',
	  cast(Breakfast09CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast09CholesterolGramsPerEntry',
	  cast(Breakfast09TransFatGramsPerEntry        as decimal(8,1))                 'breakfast09TransFatGramsPerEntry',
	  cast(Breakfast09DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast09DietaryFibreGramsPerEntry',
	  cast(Breakfast09SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast09SolubleFibreGramsPerEntry',
	  cast(Breakfast09InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast09InsolubleFibreGramsPerEntry',
	  cast(Breakfast09SodiumGramsPerEntry          as decimal(8,2))                 'breakfast09SodiumGramsPerEntry',
	  cast(Breakfast09AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast09AlcoholGramsPerEntry',
	        Breakfast10FoodDescription                                               'breakfast10FoodDescription',
	        Breakfast10AmountDescription                                             'breakfast10AmountDescription',
	  cast(Breakfast10EnergyKiloJoulesPerEntry     as decimal(8,0))                 'breakfast10EnergyKiloJoulesPerEntry',
	  cast(Breakfast10ProteinGramsPerEntry         as decimal(8,1))                 'breakfast10ProteinGramsPerEntry',
	  cast(Breakfast10CarbohydrateGramsPerEntry    as decimal(8,1))                 'breakfast10CarbohydrateGramsPerEntry',
	  cast(Breakfast10SugarGramsPerEntry           as decimal(8,1))                 'breakfast10SugarGramsPerEntry',
	  cast(Breakfast10StarchGramsPerEntry          as decimal(8,1))                 'breakfast10StarchGramsPerEntry',
	  cast(Breakfast10FatGramsPerEntry             as decimal(8,1))                 'breakfast10FatGramsPerEntry',
	  cast(Breakfast10SaturatedFatGramsPerEntry    as decimal(8,1))                 'breakfast10SaturatedFatGramsPerEntry',
	  cast(Breakfast10UnsaturatedFatGramsPerEntry  as decimal(8,1))                 'breakfast10UnsaturatedFatGramsPerEntry',
	  cast(Breakfast10CholesterolGramsPerEntry     as decimal(8,1))                 'breakfast10CholesterolGramsPerEntry',
	  cast(Breakfast10TransFatGramsPerEntry        as decimal(8,1))                 'breakfast10TransFatGramsPerEntry',
	  cast(Breakfast10DietaryFibreGramsPerEntry    as decimal(8,1))                 'breakfast10DietaryFibreGramsPerEntry',
	  cast(Breakfast10SolubleFibreGramsPerEntry    as decimal(8,1))                 'breakfast10SolubleFibreGramsPerEntry',
	  cast(Breakfast10InsolubleFibreGramsPerEntry  as decimal(8,1))                 'breakfast10InsolubleFibreGramsPerEntry',
	  cast(Breakfast10SodiumGramsPerEntry          as decimal(8,2))                 'breakfast10SodiumGramsPerEntry',
	  cast(Breakfast10AlcoholGramsPerEntry         as decimal(8,1))                 'breakfast10AlcoholGramsPerEntry',

	        Lunch01FoodDescription                                                   'lunch01FoodDescription',
	        Lunch01AmountDescription                                                 'lunch01AmountDescription',
	  cast(Lunch01EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch01EnergyKiloJoulesPerEntry',
	  cast(Lunch01ProteinGramsPerEntry             as decimal(8,1))                 'lunch01ProteinGramsPerEntry',
	  cast(Lunch01CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch01CarbohydrateGramsPerEntry',
	  cast(Lunch01SugarGramsPerEntry               as decimal(8,1))                 'lunch01SugarGramsPerEntry',
	  cast(Lunch01StarchGramsPerEntry              as decimal(8,1))                 'lunch01StarchGramsPerEntry',
	  cast(Lunch01FatGramsPerEntry                 as decimal(8,1))                 'lunch01FatGramsPerEntry',
	  cast(Lunch01SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch01SaturatedFatGramsPerEntry',
	  cast(Lunch01UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch01UnsaturatedFatGramsPerEntry',
	  cast(Lunch01CholesterolGramsPerEntry         as decimal(8,1))                 'lunch01CholesterolGramsPerEntry',
	  cast(Lunch01TransFatGramsPerEntry            as decimal(8,1))                 'lunch01TransFatGramsPerEntry',
	  cast(Lunch01DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch01DietaryFibreGramsPerEntry',
	  cast(Lunch01SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch01SolubleFibreGramsPerEntry',
	  cast(Lunch01InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch01InsolubleFibreGramsPerEntry',
	  cast(Lunch01SodiumGramsPerEntry              as decimal(8,2))                 'lunch01SodiumGramsPerEntry',
	  cast(Lunch01AlcoholGramsPerEntry             as decimal(8,1))                 'lunch01AlcoholGramsPerEntry',
	        Lunch02FoodDescription                                                   'lunch02FoodDescription',
	        Lunch02AmountDescription                                                 'lunch02AmountDescription',
	  cast(Lunch02EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch02EnergyKiloJoulesPerEntry',
	  cast(Lunch02ProteinGramsPerEntry             as decimal(8,1))                 'lunch02ProteinGramsPerEntry',
	  cast(Lunch02CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch02CarbohydrateGramsPerEntry',
	  cast(Lunch02SugarGramsPerEntry               as decimal(8,1))                 'lunch02SugarGramsPerEntry',
	  cast(Lunch02StarchGramsPerEntry              as decimal(8,1))                 'lunch02StarchGramsPerEntry',
	  cast(Lunch02FatGramsPerEntry                 as decimal(8,1))                 'lunch02FatGramsPerEntry',
	  cast(Lunch02SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch02SaturatedFatGramsPerEntry',
	  cast(Lunch02UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch02UnsaturatedFatGramsPerEntry',
	  cast(Lunch02CholesterolGramsPerEntry         as decimal(8,1))                 'lunch02CholesterolGramsPerEntry',
	  cast(Lunch02TransFatGramsPerEntry            as decimal(8,1))                 'lunch02TransFatGramsPerEntry',
	  cast(Lunch02DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch02DietaryFibreGramsPerEntry',
	  cast(Lunch02SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch02SolubleFibreGramsPerEntry',
	  cast(Lunch02InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch02InsolubleFibreGramsPerEntry',
	  cast(Lunch02SodiumGramsPerEntry              as decimal(8,2))                 'lunch02SodiumGramsPerEntry',
	  cast(Lunch02AlcoholGramsPerEntry             as decimal(8,1))                 'lunch02AlcoholGramsPerEntry',
	        Lunch03FoodDescription                                                   'lunch03FoodDescription',
	        Lunch03AmountDescription                                                 'lunch03AmountDescription',
	  cast(Lunch03EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch03EnergyKiloJoulesPerEntry',
	  cast(Lunch03ProteinGramsPerEntry             as decimal(8,1))                 'lunch03ProteinGramsPerEntry',
	  cast(Lunch03CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch03CarbohydrateGramsPerEntry',
	  cast(Lunch03SugarGramsPerEntry               as decimal(8,1))                 'lunch03SugarGramsPerEntry',
	  cast(Lunch03StarchGramsPerEntry              as decimal(8,1))                 'lunch03StarchGramsPerEntry',
	  cast(Lunch03FatGramsPerEntry                 as decimal(8,1))                 'lunch03FatGramsPerEntry',
	  cast(Lunch03SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch03SaturatedFatGramsPerEntry',
	  cast(Lunch03UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch03UnsaturatedFatGramsPerEntry',
	  cast(Lunch03CholesterolGramsPerEntry         as decimal(8,1))                 'lunch03CholesterolGramsPerEntry',
	  cast(Lunch03TransFatGramsPerEntry            as decimal(8,1))                 'lunch03TransFatGramsPerEntry',
	  cast(Lunch03DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch03DietaryFibreGramsPerEntry',
	  cast(Lunch03SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch03SolubleFibreGramsPerEntry',
	  cast(Lunch03InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch03InsolubleFibreGramsPerEntry',
	  cast(Lunch03SodiumGramsPerEntry              as decimal(8,2))                 'lunch03SodiumGramsPerEntry',
	  cast(Lunch03AlcoholGramsPerEntry             as decimal(8,1))                 'lunch03AlcoholGramsPerEntry',
	        Lunch04FoodDescription                                                   'lunch04FoodDescription',
	        Lunch04AmountDescription                                                 'lunch04AmountDescription',
	  cast(Lunch04EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch04EnergyKiloJoulesPerEntry',
	  cast(Lunch04ProteinGramsPerEntry             as decimal(8,1))                 'lunch04ProteinGramsPerEntry',
	  cast(Lunch04CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch04CarbohydrateGramsPerEntry',
	  cast(Lunch04SugarGramsPerEntry               as decimal(8,1))                 'lunch04SugarGramsPerEntry',
	  cast(Lunch04StarchGramsPerEntry              as decimal(8,1))                 'lunch04StarchGramsPerEntry',
	  cast(Lunch04FatGramsPerEntry                 as decimal(8,1))                 'lunch04FatGramsPerEntry',
	  cast(Lunch04SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch04SaturatedFatGramsPerEntry',
	  cast(Lunch04UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch04UnsaturatedFatGramsPerEntry',
	  cast(Lunch04CholesterolGramsPerEntry         as decimal(8,1))                 'lunch04CholesterolGramsPerEntry',
	  cast(Lunch04TransFatGramsPerEntry            as decimal(8,1))                 'lunch04TransFatGramsPerEntry',
	  cast(Lunch04DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch04DietaryFibreGramsPerEntry',
	  cast(Lunch04SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch04SolubleFibreGramsPerEntry',
	  cast(Lunch04InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch04InsolubleFibreGramsPerEntry',
	  cast(Lunch04SodiumGramsPerEntry              as decimal(8,2))                 'lunch04SodiumGramsPerEntry',
	  cast(Lunch04AlcoholGramsPerEntry             as decimal(8,1))                 'lunch04AlcoholGramsPerEntry',
	        Lunch05FoodDescription                                                   'lunch05FoodDescription',
	        Lunch05AmountDescription                                                 'lunch05AmountDescription',
	  cast(Lunch05EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch05EnergyKiloJoulesPerEntry',
	  cast(Lunch05ProteinGramsPerEntry             as decimal(8,1))                 'lunch05ProteinGramsPerEntry',
	  cast(Lunch05CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch05CarbohydrateGramsPerEntry',
	  cast(Lunch05SugarGramsPerEntry               as decimal(8,1))                 'lunch05SugarGramsPerEntry',
	  cast(Lunch05StarchGramsPerEntry              as decimal(8,1))                 'lunch05StarchGramsPerEntry',
	  cast(Lunch05FatGramsPerEntry                 as decimal(8,1))                 'lunch05FatGramsPerEntry',
	  cast(Lunch05SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch05SaturatedFatGramsPerEntry',
	  cast(Lunch05UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch05UnsaturatedFatGramsPerEntry',
	  cast(Lunch05CholesterolGramsPerEntry         as decimal(8,1))                 'lunch05CholesterolGramsPerEntry',
	  cast(Lunch05TransFatGramsPerEntry            as decimal(8,1))                 'lunch05TransFatGramsPerEntry',
	  cast(Lunch05DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch05DietaryFibreGramsPerEntry',
	  cast(Lunch05SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch05SolubleFibreGramsPerEntry',
	  cast(Lunch05InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch05InsolubleFibreGramsPerEntry',
	  cast(Lunch05SodiumGramsPerEntry              as decimal(8,2))                 'lunch05SodiumGramsPerEntry',
	  cast(Lunch05AlcoholGramsPerEntry             as decimal(8,1))                 'lunch05AlcoholGramsPerEntry',
	        Lunch06FoodDescription                                                   'lunch06FoodDescription',
	        Lunch06AmountDescription                                                 'lunch06AmountDescription',
	  cast(Lunch06EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch06EnergyKiloJoulesPerEntry',
	  cast(Lunch06ProteinGramsPerEntry             as decimal(8,1))                 'lunch06ProteinGramsPerEntry',
	  cast(Lunch06CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch06CarbohydrateGramsPerEntry',
	  cast(Lunch06SugarGramsPerEntry               as decimal(8,1))                 'lunch06SugarGramsPerEntry',
	  cast(Lunch06StarchGramsPerEntry              as decimal(8,1))                 'lunch06StarchGramsPerEntry',
	  cast(Lunch06FatGramsPerEntry                 as decimal(8,1))                 'lunch06FatGramsPerEntry',
	  cast(Lunch06SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch06SaturatedFatGramsPerEntry',
	  cast(Lunch06UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch06UnsaturatedFatGramsPerEntry',
	  cast(Lunch06CholesterolGramsPerEntry         as decimal(8,1))                 'lunch06CholesterolGramsPerEntry',
	  cast(Lunch06TransFatGramsPerEntry            as decimal(8,1))                 'lunch06TransFatGramsPerEntry',
	  cast(Lunch06DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch06DietaryFibreGramsPerEntry',
	  cast(Lunch06SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch06SolubleFibreGramsPerEntry',
	  cast(Lunch06InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch06InsolubleFibreGramsPerEntry',
	  cast(Lunch06SodiumGramsPerEntry              as decimal(8,2))                 'lunch06SodiumGramsPerEntry',
	  cast(Lunch06AlcoholGramsPerEntry             as decimal(8,1))                 'lunch06AlcoholGramsPerEntry',
	        Lunch07FoodDescription                                                   'lunch07FoodDescription',
	        Lunch07AmountDescription                                                 'lunch07AmountDescription',
	  cast(Lunch07EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch07EnergyKiloJoulesPerEntry',
	  cast(Lunch07ProteinGramsPerEntry             as decimal(8,1))                 'lunch07ProteinGramsPerEntry',
	  cast(Lunch07CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch07CarbohydrateGramsPerEntry',
	  cast(Lunch07SugarGramsPerEntry               as decimal(8,1))                 'lunch07SugarGramsPerEntry',
	  cast(Lunch07StarchGramsPerEntry              as decimal(8,1))                 'lunch07StarchGramsPerEntry',
	  cast(Lunch07FatGramsPerEntry                 as decimal(8,1))                 'lunch07FatGramsPerEntry',
	  cast(Lunch07SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch07SaturatedFatGramsPerEntry',
	  cast(Lunch07UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch07UnsaturatedFatGramsPerEntry',
	  cast(Lunch07CholesterolGramsPerEntry         as decimal(8,1))                 'lunch07CholesterolGramsPerEntry',
	  cast(Lunch07TransFatGramsPerEntry            as decimal(8,1))                 'lunch07TransFatGramsPerEntry',
	  cast(Lunch07DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch07DietaryFibreGramsPerEntry',
	  cast(Lunch07SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch07SolubleFibreGramsPerEntry',
	  cast(Lunch07InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch07InsolubleFibreGramsPerEntry',
	  cast(Lunch07SodiumGramsPerEntry              as decimal(8,2))                 'lunch07SodiumGramsPerEntry',
	  cast(Lunch07AlcoholGramsPerEntry             as decimal(8,1))                 'lunch07AlcoholGramsPerEntry',
	        Lunch08FoodDescription                                                   'lunch08FoodDescription',
	        Lunch08AmountDescription                                                 'lunch08AmountDescription',
	  cast(Lunch08EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch08EnergyKiloJoulesPerEntry',
	  cast(Lunch08ProteinGramsPerEntry             as decimal(8,1))                 'lunch08ProteinGramsPerEntry',
	  cast(Lunch08CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch08CarbohydrateGramsPerEntry',
	  cast(Lunch08SugarGramsPerEntry               as decimal(8,1))                 'lunch08SugarGramsPerEntry',
	  cast(Lunch08StarchGramsPerEntry              as decimal(8,1))                 'lunch08StarchGramsPerEntry',
	  cast(Lunch08FatGramsPerEntry                 as decimal(8,1))                 'lunch08FatGramsPerEntry',
	  cast(Lunch08SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch08SaturatedFatGramsPerEntry',
	  cast(Lunch08UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch08UnsaturatedFatGramsPerEntry',
	  cast(Lunch08CholesterolGramsPerEntry         as decimal(8,1))                 'lunch08CholesterolGramsPerEntry',
	  cast(Lunch08TransFatGramsPerEntry            as decimal(8,1))                 'lunch08TransFatGramsPerEntry',
	  cast(Lunch08DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch08DietaryFibreGramsPerEntry',
	  cast(Lunch08SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch08SolubleFibreGramsPerEntry',
	  cast(Lunch08InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch08InsolubleFibreGramsPerEntry',
	  cast(Lunch08SodiumGramsPerEntry              as decimal(8,2))                 'lunch08SodiumGramsPerEntry',
	  cast(Lunch08AlcoholGramsPerEntry             as decimal(8,1))                 'lunch08AlcoholGramsPerEntry',
	        Lunch09FoodDescription                                                   'lunch09FoodDescription',
	        Lunch09AmountDescription                                                 'lunch09AmountDescription',
	  cast(Lunch09EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch09EnergyKiloJoulesPerEntry',
	  cast(Lunch09ProteinGramsPerEntry             as decimal(8,1))                 'lunch09ProteinGramsPerEntry',
	  cast(Lunch09CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch09CarbohydrateGramsPerEntry',
	  cast(Lunch09SugarGramsPerEntry               as decimal(8,1))                 'lunch09SugarGramsPerEntry',
	  cast(Lunch09StarchGramsPerEntry              as decimal(8,1))                 'lunch09StarchGramsPerEntry',
	  cast(Lunch09FatGramsPerEntry                 as decimal(8,1))                 'lunch09FatGramsPerEntry',
	  cast(Lunch09SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch09SaturatedFatGramsPerEntry',
	  cast(Lunch09UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch09UnsaturatedFatGramsPerEntry',
	  cast(Lunch09CholesterolGramsPerEntry         as decimal(8,1))                 'lunch09CholesterolGramsPerEntry',
	  cast(Lunch09TransFatGramsPerEntry            as decimal(8,1))                 'lunch09TransFatGramsPerEntry',
	  cast(Lunch09DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch09DietaryFibreGramsPerEntry',
	  cast(Lunch09SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch09SolubleFibreGramsPerEntry',
	  cast(Lunch09InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch09InsolubleFibreGramsPerEntry',
	  cast(Lunch09SodiumGramsPerEntry              as decimal(8,2))                 'lunch09SodiumGramsPerEntry',
	  cast(Lunch09AlcoholGramsPerEntry             as decimal(8,1))                 'lunch09AlcoholGramsPerEntry',
	        Lunch10FoodDescription                                                   'lunch10FoodDescription',
	        Lunch10AmountDescription                                                 'lunch10AmountDescription',
	  cast(Lunch10EnergyKiloJoulesPerEntry         as decimal(8,0))                 'lunch10EnergyKiloJoulesPerEntry',
	  cast(Lunch10ProteinGramsPerEntry             as decimal(8,1))                 'lunch10ProteinGramsPerEntry',
	  cast(Lunch10CarbohydrateGramsPerEntry        as decimal(8,1))                 'lunch10CarbohydrateGramsPerEntry',
	  cast(Lunch10SugarGramsPerEntry               as decimal(8,1))                 'lunch10SugarGramsPerEntry',
	  cast(Lunch10StarchGramsPerEntry              as decimal(8,1))                 'lunch10StarchGramsPerEntry',
	  cast(Lunch10FatGramsPerEntry                 as decimal(8,1))                 'lunch10FatGramsPerEntry',
	  cast(Lunch10SaturatedFatGramsPerEntry        as decimal(8,1))                 'lunch10SaturatedFatGramsPerEntry',
	  cast(Lunch10UnsaturatedFatGramsPerEntry      as decimal(8,1))                 'lunch10UnsaturatedFatGramsPerEntry',
	  cast(Lunch10CholesterolGramsPerEntry         as decimal(8,1))                 'lunch10CholesterolGramsPerEntry',
	  cast(Lunch10TransFatGramsPerEntry            as decimal(8,1))                 'lunch10TransFatGramsPerEntry',
	  cast(Lunch10DietaryFibreGramsPerEntry        as decimal(8,1))                 'lunch10DietaryFibreGramsPerEntry',
	  cast(Lunch10SolubleFibreGramsPerEntry        as decimal(8,1))                 'lunch10SolubleFibreGramsPerEntry',
	  cast(Lunch10InsolubleFibreGramsPerEntry      as decimal(8,1))                 'lunch10InsolubleFibreGramsPerEntry',
	  cast(Lunch10SodiumGramsPerEntry              as decimal(8,2))                 'lunch10SodiumGramsPerEntry',
	  cast(Lunch10AlcoholGramsPerEntry             as decimal(8,1))                 'lunch10AlcoholGramsPerEntry',

	        Dinner01FoodDescription                                                  'dinner01FoodDescription',
	        Dinner01AmountDescription                                                'dinner01AmountDescription',
	  cast(Dinner01EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner01EnergyKiloJoulesPerEntry',
	  cast(Dinner01ProteinGramsPerEntry            as decimal(8,1))                 'dinner01ProteinGramsPerEntry',
	  cast(Dinner01CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner01CarbohydrateGramsPerEntry',
	  cast(Dinner01SugarGramsPerEntry              as decimal(8,1))                 'dinner01SugarGramsPerEntry',
	  cast(Dinner01StarchGramsPerEntry             as decimal(8,1))                 'dinner01StarchGramsPerEntry',
	  cast(Dinner01FatGramsPerEntry                as decimal(8,1))                 'dinner01FatGramsPerEntry',
	  cast(Dinner01SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner01SaturatedFatGramsPerEntry',
	  cast(Dinner01UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner01UnsaturatedFatGramsPerEntry',
	  cast(Dinner01CholesterolGramsPerEntry        as decimal(8,1))                 'dinner01CholesterolGramsPerEntry',
	  cast(Dinner01TransFatGramsPerEntry           as decimal(8,1))                 'dinner01TransFatGramsPerEntry',
	  cast(Dinner01DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner01DietaryFibreGramsPerEntry',
	  cast(Dinner01SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner01SolubleFibreGramsPerEntry',
	  cast(Dinner01InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner01InsolubleFibreGramsPerEntry',
	  cast(Dinner01SodiumGramsPerEntry             as decimal(8,2))                 'dinner01SodiumGramsPerEntry',
	  cast(Dinner01AlcoholGramsPerEntry            as decimal(8,1))                 'dinner01AlcoholGramsPerEntry',
	        Dinner02FoodDescription                                                  'dinner02FoodDescription',
	        Dinner02AmountDescription                                                'dinner02AmountDescription',
	  cast(Dinner02EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner02EnergyKiloJoulesPerEntry',
	  cast(Dinner02ProteinGramsPerEntry            as decimal(8,1))                 'dinner02ProteinGramsPerEntry',
	  cast(Dinner02CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner02CarbohydrateGramsPerEntry',
	  cast(Dinner02SugarGramsPerEntry              as decimal(8,1))                 'dinner02SugarGramsPerEntry',
	  cast(Dinner02StarchGramsPerEntry             as decimal(8,1))                 'dinner02StarchGramsPerEntry',
	  cast(Dinner02FatGramsPerEntry                as decimal(8,1))                 'dinner02FatGramsPerEntry',
	  cast(Dinner02SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner02SaturatedFatGramsPerEntry',
	  cast(Dinner02UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner02UnsaturatedFatGramsPerEntry',
	  cast(Dinner02CholesterolGramsPerEntry        as decimal(8,1))                 'dinner02CholesterolGramsPerEntry',
	  cast(Dinner02TransFatGramsPerEntry           as decimal(8,1))                 'dinner02TransFatGramsPerEntry',
	  cast(Dinner02DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner02DietaryFibreGramsPerEntry',
	  cast(Dinner02SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner02SolubleFibreGramsPerEntry',
	  cast(Dinner02InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner02InsolubleFibreGramsPerEntry',
	  cast(Dinner02SodiumGramsPerEntry             as decimal(8,2))                 'dinner02SodiumGramsPerEntry',
	  cast(Dinner02AlcoholGramsPerEntry            as decimal(8,1))                 'dinner02AlcoholGramsPerEntry',
	        Dinner03FoodDescription                                                  'dinner03FoodDescription',
	        Dinner03AmountDescription                                                'dinner03AmountDescription',
	  cast(Dinner03EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner03EnergyKiloJoulesPerEntry',
	  cast(Dinner03ProteinGramsPerEntry            as decimal(8,1))                 'dinner03ProteinGramsPerEntry',
	  cast(Dinner03CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner03CarbohydrateGramsPerEntry',
	  cast(Dinner03SugarGramsPerEntry              as decimal(8,1))                 'dinner03SugarGramsPerEntry',
	  cast(Dinner03StarchGramsPerEntry             as decimal(8,1))                 'dinner03StarchGramsPerEntry',
	  cast(Dinner03FatGramsPerEntry                as decimal(8,1))                 'dinner03FatGramsPerEntry',
	  cast(Dinner03SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner03SaturatedFatGramsPerEntry',
	  cast(Dinner03UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner03UnsaturatedFatGramsPerEntry',
	  cast(Dinner03CholesterolGramsPerEntry        as decimal(8,1))                 'dinner03CholesterolGramsPerEntry',
	  cast(Dinner03TransFatGramsPerEntry           as decimal(8,1))                 'dinner03TransFatGramsPerEntry',
	  cast(Dinner03DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner03DietaryFibreGramsPerEntry',
	  cast(Dinner03SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner03SolubleFibreGramsPerEntry',
	  cast(Dinner03InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner03InsolubleFibreGramsPerEntry',
	  cast(Dinner03SodiumGramsPerEntry             as decimal(8,2))                 'dinner03SodiumGramsPerEntry',
	  cast(Dinner03AlcoholGramsPerEntry            as decimal(8,1))                 'dinner03AlcoholGramsPerEntry',
	        Dinner04FoodDescription                                                  'dinner04FoodDescription',
	        Dinner04AmountDescription                                                'dinner04AmountDescription',
	  cast(Dinner04EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner04EnergyKiloJoulesPerEntry',
	  cast(Dinner04ProteinGramsPerEntry            as decimal(8,1))                 'dinner04ProteinGramsPerEntry',
	  cast(Dinner04CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner04CarbohydrateGramsPerEntry',
	  cast(Dinner04SugarGramsPerEntry              as decimal(8,1))                 'dinner04SugarGramsPerEntry',
	  cast(Dinner04StarchGramsPerEntry             as decimal(8,1))                 'dinner04StarchGramsPerEntry',
	  cast(Dinner04FatGramsPerEntry                as decimal(8,1))                 'dinner04FatGramsPerEntry',
	  cast(Dinner04SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner04SaturatedFatGramsPerEntry',
	  cast(Dinner04UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner04UnsaturatedFatGramsPerEntry',
	  cast(Dinner04CholesterolGramsPerEntry        as decimal(8,1))                 'dinner04CholesterolGramsPerEntry',
	  cast(Dinner04TransFatGramsPerEntry           as decimal(8,1))                 'dinner04TransFatGramsPerEntry',
	  cast(Dinner04DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner04DietaryFibreGramsPerEntry',
	  cast(Dinner04SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner04SolubleFibreGramsPerEntry',
	  cast(Dinner04InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner04InsolubleFibreGramsPerEntry',
	  cast(Dinner04SodiumGramsPerEntry             as decimal(8,2))                 'dinner04SodiumGramsPerEntry',
	  cast(Dinner04AlcoholGramsPerEntry            as decimal(8,1))                 'dinner04AlcoholGramsPerEntry',
	        Dinner05FoodDescription                                                  'dinner05FoodDescription',
	        Dinner05AmountDescription                                                'dinner05AmountDescription',
	  cast(Dinner05EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner05EnergyKiloJoulesPerEntry',
	  cast(Dinner05ProteinGramsPerEntry            as decimal(8,1))                 'dinner05ProteinGramsPerEntry',
	  cast(Dinner05CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner05CarbohydrateGramsPerEntry',
	  cast(Dinner05SugarGramsPerEntry              as decimal(8,1))                 'dinner05SugarGramsPerEntry',
	  cast(Dinner05StarchGramsPerEntry             as decimal(8,1))                 'dinner05StarchGramsPerEntry',
	  cast(Dinner05FatGramsPerEntry                as decimal(8,1))                 'dinner05FatGramsPerEntry',
	  cast(Dinner05SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner05SaturatedFatGramsPerEntry',
	  cast(Dinner05UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner05UnsaturatedFatGramsPerEntry',
	  cast(Dinner05CholesterolGramsPerEntry        as decimal(8,1))                 'dinner05CholesterolGramsPerEntry',
	  cast(Dinner05TransFatGramsPerEntry           as decimal(8,1))                 'dinner05TransFatGramsPerEntry',
	  cast(Dinner05DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner05DietaryFibreGramsPerEntry',
	  cast(Dinner05SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner05SolubleFibreGramsPerEntry',
	  cast(Dinner05InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner05InsolubleFibreGramsPerEntry',
	  cast(Dinner05SodiumGramsPerEntry             as decimal(8,2))                 'dinner05SodiumGramsPerEntry',
	  cast(Dinner05AlcoholGramsPerEntry            as decimal(8,1))                 'dinner05AlcoholGramsPerEntry',
	        Dinner06FoodDescription                                                  'dinner06FoodDescription',
	        Dinner06AmountDescription                                                'dinner06AmountDescription',
	  cast(Dinner06EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner06EnergyKiloJoulesPerEntry',
	  cast(Dinner06ProteinGramsPerEntry            as decimal(8,1))                 'dinner06ProteinGramsPerEntry',
	  cast(Dinner06CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner06CarbohydrateGramsPerEntry',
	  cast(Dinner06SugarGramsPerEntry              as decimal(8,1))                 'dinner06SugarGramsPerEntry',
	  cast(Dinner06StarchGramsPerEntry             as decimal(8,1))                 'dinner06StarchGramsPerEntry',
	  cast(Dinner06FatGramsPerEntry                as decimal(8,1))                 'dinner06FatGramsPerEntry',
	  cast(Dinner06SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner06SaturatedFatGramsPerEntry',
	  cast(Dinner06UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner06UnsaturatedFatGramsPerEntry',
	  cast(Dinner06CholesterolGramsPerEntry        as decimal(8,1))                 'dinner06CholesterolGramsPerEntry',
	  cast(Dinner06TransFatGramsPerEntry           as decimal(8,1))                 'dinner06TransFatGramsPerEntry',
	  cast(Dinner06DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner06DietaryFibreGramsPerEntry',
	  cast(Dinner06SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner06SolubleFibreGramsPerEntry',
	  cast(Dinner06InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner06InsolubleFibreGramsPerEntry',
	  cast(Dinner06SodiumGramsPerEntry             as decimal(8,2))                 'dinner06SodiumGramsPerEntry',
	  cast(Dinner06AlcoholGramsPerEntry            as decimal(8,1))                 'dinner06AlcoholGramsPerEntry',
	        Dinner07FoodDescription                                                  'dinner07FoodDescription',
	        Dinner07AmountDescription                                                'dinner07AmountDescription',
	  cast(Dinner07EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner07EnergyKiloJoulesPerEntry',
	  cast(Dinner07ProteinGramsPerEntry            as decimal(8,1))                 'dinner07ProteinGramsPerEntry',
	  cast(Dinner07CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner07CarbohydrateGramsPerEntry',
	  cast(Dinner07SugarGramsPerEntry              as decimal(8,1))                 'dinner07SugarGramsPerEntry',
	  cast(Dinner07StarchGramsPerEntry             as decimal(8,1))                 'dinner07StarchGramsPerEntry',
	  cast(Dinner07FatGramsPerEntry                as decimal(8,1))                 'dinner07FatGramsPerEntry',
	  cast(Dinner07SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner07SaturatedFatGramsPerEntry',
	  cast(Dinner07UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner07UnsaturatedFatGramsPerEntry',
	  cast(Dinner07CholesterolGramsPerEntry        as decimal(8,1))                 'dinner07CholesterolGramsPerEntry',
	  cast(Dinner07TransFatGramsPerEntry           as decimal(8,1))                 'dinner07TransFatGramsPerEntry',
	  cast(Dinner07DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner07DietaryFibreGramsPerEntry',
	  cast(Dinner07SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner07SolubleFibreGramsPerEntry',
	  cast(Dinner07InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner07InsolubleFibreGramsPerEntry',
	  cast(Dinner07SodiumGramsPerEntry             as decimal(8,2))                 'dinner07SodiumGramsPerEntry',
	  cast(Dinner07AlcoholGramsPerEntry            as decimal(8,1))                 'dinner07AlcoholGramsPerEntry',
	        Dinner08FoodDescription                                                  'dinner08FoodDescription',
	        Dinner08AmountDescription                                                'dinner08AmountDescription',
	  cast(Dinner08EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner08EnergyKiloJoulesPerEntry',
	  cast(Dinner08ProteinGramsPerEntry            as decimal(8,1))                 'dinner08ProteinGramsPerEntry',
	  cast(Dinner08CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner08CarbohydrateGramsPerEntry',
	  cast(Dinner08SugarGramsPerEntry              as decimal(8,1))                 'dinner08SugarGramsPerEntry',
	  cast(Dinner08StarchGramsPerEntry             as decimal(8,1))                 'dinner08StarchGramsPerEntry',
	  cast(Dinner08FatGramsPerEntry                as decimal(8,1))                 'dinner08FatGramsPerEntry',
	  cast(Dinner08SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner08SaturatedFatGramsPerEntry',
	  cast(Dinner08UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner08UnsaturatedFatGramsPerEntry',
	  cast(Dinner08CholesterolGramsPerEntry        as decimal(8,1))                 'dinner08CholesterolGramsPerEntry',
	  cast(Dinner08TransFatGramsPerEntry           as decimal(8,1))                 'dinner08TransFatGramsPerEntry',
	  cast(Dinner08DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner08DietaryFibreGramsPerEntry',
	  cast(Dinner08SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner08SolubleFibreGramsPerEntry',
	  cast(Dinner08InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner08InsolubleFibreGramsPerEntry',
	  cast(Dinner08SodiumGramsPerEntry             as decimal(8,2))                 'dinner08SodiumGramsPerEntry',
	  cast(Dinner08AlcoholGramsPerEntry            as decimal(8,1))                 'dinner08AlcoholGramsPerEntry',
	        Dinner09FoodDescription                                                  'dinner09FoodDescription',
	        Dinner09AmountDescription                                                'dinner09AmountDescription',
	  cast(Dinner09EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner09EnergyKiloJoulesPerEntry',
	  cast(Dinner09ProteinGramsPerEntry            as decimal(8,1))                 'dinner09ProteinGramsPerEntry',
	  cast(Dinner09CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner09CarbohydrateGramsPerEntry',
	  cast(Dinner09SugarGramsPerEntry              as decimal(8,1))                 'dinner09SugarGramsPerEntry',
	  cast(Dinner09StarchGramsPerEntry             as decimal(8,1))                 'dinner09StarchGramsPerEntry',
	  cast(Dinner09FatGramsPerEntry                as decimal(8,1))                 'dinner09FatGramsPerEntry',
	  cast(Dinner09SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner09SaturatedFatGramsPerEntry',
	  cast(Dinner09UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner09UnsaturatedFatGramsPerEntry',
	  cast(Dinner09CholesterolGramsPerEntry        as decimal(8,1))                 'dinner09CholesterolGramsPerEntry',
	  cast(Dinner09TransFatGramsPerEntry           as decimal(8,1))                 'dinner09TransFatGramsPerEntry',
	  cast(Dinner09DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner09DietaryFibreGramsPerEntry',
	  cast(Dinner09SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner09SolubleFibreGramsPerEntry',
	  cast(Dinner09InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner09InsolubleFibreGramsPerEntry',
	  cast(Dinner09SodiumGramsPerEntry             as decimal(8,2))                 'dinner09SodiumGramsPerEntry',
	  cast(Dinner09AlcoholGramsPerEntry            as decimal(8,1))                 'dinner09AlcoholGramsPerEntry',
	        Dinner10FoodDescription                                                  'dinner10FoodDescription',
	        Dinner10AmountDescription                                                'dinner10AmountDescription',
	  cast(Dinner10EnergyKiloJoulesPerEntry        as decimal(8,0))                 'dinner10EnergyKiloJoulesPerEntry',
	  cast(Dinner10ProteinGramsPerEntry            as decimal(8,1))                 'dinner10ProteinGramsPerEntry',
	  cast(Dinner10CarbohydrateGramsPerEntry       as decimal(8,1))                 'dinner10CarbohydrateGramsPerEntry',
	  cast(Dinner10SugarGramsPerEntry              as decimal(8,1))                 'dinner10SugarGramsPerEntry',
	  cast(Dinner10StarchGramsPerEntry             as decimal(8,1))                 'dinner10StarchGramsPerEntry',
	  cast(Dinner10FatGramsPerEntry                as decimal(8,1))                 'dinner10FatGramsPerEntry',
	  cast(Dinner10SaturatedFatGramsPerEntry       as decimal(8,1))                 'dinner10SaturatedFatGramsPerEntry',
	  cast(Dinner10UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'dinner10UnsaturatedFatGramsPerEntry',
	  cast(Dinner10CholesterolGramsPerEntry        as decimal(8,1))                 'dinner10CholesterolGramsPerEntry',
	  cast(Dinner10TransFatGramsPerEntry           as decimal(8,1))                 'dinner10TransFatGramsPerEntry',
	  cast(Dinner10DietaryFibreGramsPerEntry       as decimal(8,1))                 'dinner10DietaryFibreGramsPerEntry',
	  cast(Dinner10SolubleFibreGramsPerEntry       as decimal(8,1))                 'dinner10SolubleFibreGramsPerEntry',
	  cast(Dinner10InsolubleFibreGramsPerEntry     as decimal(8,1))                 'dinner10InsolubleFibreGramsPerEntry',
	  cast(Dinner10SodiumGramsPerEntry             as decimal(8,2))                 'dinner10SodiumGramsPerEntry',
	  cast(Dinner10AlcoholGramsPerEntry            as decimal(8,1))                 'dinner10AlcoholGramsPerEntry',

	        Snacks01FoodDescription                                                  'snacks01FoodDescription',
	        Snacks01AmountDescription                                                'snacks01AmountDescription',
	  cast(Snacks01EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks01EnergyKiloJoulesPerEntry',
	  cast(Snacks01ProteinGramsPerEntry            as decimal(8,1))                 'snacks01ProteinGramsPerEntry',
	  cast(Snacks01CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks01CarbohydrateGramsPerEntry',
	  cast(Snacks01SugarGramsPerEntry              as decimal(8,1))                 'snacks01SugarGramsPerEntry',
	  cast(Snacks01StarchGramsPerEntry             as decimal(8,1))                 'snacks01StarchGramsPerEntry',
	  cast(Snacks01FatGramsPerEntry                as decimal(8,1))                 'snacks01FatGramsPerEntry',
	  cast(Snacks01SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks01SaturatedFatGramsPerEntry',
	  cast(Snacks01UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks01UnsaturatedFatGramsPerEntry',
	  cast(Snacks01CholesterolGramsPerEntry        as decimal(8,1))                 'snacks01CholesterolGramsPerEntry',
	  cast(Snacks01TransFatGramsPerEntry           as decimal(8,1))                 'snacks01TransFatGramsPerEntry',
	  cast(Snacks01DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks01DietaryFibreGramsPerEntry',
	  cast(Snacks01SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks01SolubleFibreGramsPerEntry',
	  cast(Snacks01InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks01InsolubleFibreGramsPerEntry',
	  cast(Snacks01SodiumGramsPerEntry             as decimal(8,2))                 'snacks01SodiumGramsPerEntry',
	  cast(Snacks01AlcoholGramsPerEntry            as decimal(8,1))                 'snacks01AlcoholGramsPerEntry',
	        Snacks02FoodDescription                                                  'snacks02FoodDescription',
	        Snacks02AmountDescription                                                'snacks02AmountDescription',
	  cast(Snacks02EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks02EnergyKiloJoulesPerEntry',
	  cast(Snacks02ProteinGramsPerEntry            as decimal(8,1))                 'snacks02ProteinGramsPerEntry',
	  cast(Snacks02CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks02CarbohydrateGramsPerEntry',
	  cast(Snacks02SugarGramsPerEntry              as decimal(8,1))                 'snacks02SugarGramsPerEntry',
	  cast(Snacks02StarchGramsPerEntry             as decimal(8,1))                 'snacks02StarchGramsPerEntry',
	  cast(Snacks02FatGramsPerEntry                as decimal(8,1))                 'snacks02FatGramsPerEntry',
	  cast(Snacks02SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks02SaturatedFatGramsPerEntry',
	  cast(Snacks02UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks02UnsaturatedFatGramsPerEntry',
	  cast(Snacks02CholesterolGramsPerEntry        as decimal(8,1))                 'snacks02CholesterolGramsPerEntry',
	  cast(Snacks02TransFatGramsPerEntry           as decimal(8,1))                 'snacks02TransFatGramsPerEntry',
	  cast(Snacks02DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks02DietaryFibreGramsPerEntry',
	  cast(Snacks02SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks02SolubleFibreGramsPerEntry',
	  cast(Snacks02InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks02InsolubleFibreGramsPerEntry',
	  cast(Snacks02SodiumGramsPerEntry             as decimal(8,2))                 'snacks02SodiumGramsPerEntry',
	  cast(Snacks02AlcoholGramsPerEntry            as decimal(8,1))                 'snacks02AlcoholGramsPerEntry',
	        Snacks03FoodDescription                                                  'snacks03FoodDescription',
	        Snacks03AmountDescription                                                'snacks03AmountDescription',
	  cast(Snacks03EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks03EnergyKiloJoulesPerEntry',
	  cast(Snacks03ProteinGramsPerEntry            as decimal(8,1))                 'snacks03ProteinGramsPerEntry',
	  cast(Snacks03CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks03CarbohydrateGramsPerEntry',
	  cast(Snacks03SugarGramsPerEntry              as decimal(8,1))                 'snacks03SugarGramsPerEntry',
	  cast(Snacks03StarchGramsPerEntry             as decimal(8,1))                 'snacks03StarchGramsPerEntry',
	  cast(Snacks03FatGramsPerEntry                as decimal(8,1))                 'snacks03FatGramsPerEntry',
	  cast(Snacks03SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks03SaturatedFatGramsPerEntry',
	  cast(Snacks03UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks03UnsaturatedFatGramsPerEntry',
	  cast(Snacks03CholesterolGramsPerEntry        as decimal(8,1))                 'snacks03CholesterolGramsPerEntry',
	  cast(Snacks03TransFatGramsPerEntry           as decimal(8,1))                 'snacks03TransFatGramsPerEntry',
	  cast(Snacks03DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks03DietaryFibreGramsPerEntry',
	  cast(Snacks03SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks03SolubleFibreGramsPerEntry',
	  cast(Snacks03InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks03InsolubleFibreGramsPerEntry',
	  cast(Snacks03SodiumGramsPerEntry             as decimal(8,2))                 'snacks03SodiumGramsPerEntry',
	  cast(Snacks03AlcoholGramsPerEntry            as decimal(8,1))                 'snacks03AlcoholGramsPerEntry',
	        Snacks04FoodDescription                                                  'snacks04FoodDescription',
	        Snacks04AmountDescription                                                'snacks04AmountDescription',
	  cast(Snacks04EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks04EnergyKiloJoulesPerEntry',
	  cast(Snacks04ProteinGramsPerEntry            as decimal(8,1))                 'snacks04ProteinGramsPerEntry',
	  cast(Snacks04CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks04CarbohydrateGramsPerEntry',
	  cast(Snacks04SugarGramsPerEntry              as decimal(8,1))                 'snacks04SugarGramsPerEntry',
	  cast(Snacks04StarchGramsPerEntry             as decimal(8,1))                 'snacks04StarchGramsPerEntry',
	  cast(Snacks04FatGramsPerEntry                as decimal(8,1))                 'snacks04FatGramsPerEntry',
	  cast(Snacks04SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks04SaturatedFatGramsPerEntry',
	  cast(Snacks04UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks04UnsaturatedFatGramsPerEntry',
	  cast(Snacks04CholesterolGramsPerEntry        as decimal(8,1))                 'snacks04CholesterolGramsPerEntry',
	  cast(Snacks04TransFatGramsPerEntry           as decimal(8,1))                 'snacks04TransFatGramsPerEntry',
	  cast(Snacks04DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks04DietaryFibreGramsPerEntry',
	  cast(Snacks04SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks04SolubleFibreGramsPerEntry',
	  cast(Snacks04InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks04InsolubleFibreGramsPerEntry',
	  cast(Snacks04SodiumGramsPerEntry             as decimal(8,2))                 'snacks04SodiumGramsPerEntry',
	  cast(Snacks04AlcoholGramsPerEntry            as decimal(8,1))                 'snacks04AlcoholGramsPerEntry',
	        Snacks05FoodDescription                                                  'snacks05FoodDescription',
	        Snacks05AmountDescription                                                'snacks05AmountDescription',
	  cast(Snacks05EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks05EnergyKiloJoulesPerEntry',
	  cast(Snacks05ProteinGramsPerEntry            as decimal(8,1))                 'snacks05ProteinGramsPerEntry',
	  cast(Snacks05CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks05CarbohydrateGramsPerEntry',
	  cast(Snacks05SugarGramsPerEntry              as decimal(8,1))                 'snacks05SugarGramsPerEntry',
	  cast(Snacks05StarchGramsPerEntry             as decimal(8,1))                 'snacks05StarchGramsPerEntry',
	  cast(Snacks05FatGramsPerEntry                as decimal(8,1))                 'snacks05FatGramsPerEntry',
	  cast(Snacks05SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks05SaturatedFatGramsPerEntry',
	  cast(Snacks05UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks05UnsaturatedFatGramsPerEntry',
	  cast(Snacks05CholesterolGramsPerEntry        as decimal(8,1))                 'snacks05CholesterolGramsPerEntry',
	  cast(Snacks05TransFatGramsPerEntry           as decimal(8,1))                 'snacks05TransFatGramsPerEntry',
	  cast(Snacks05DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks05DietaryFibreGramsPerEntry',
	  cast(Snacks05SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks05SolubleFibreGramsPerEntry',
	  cast(Snacks05InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks05InsolubleFibreGramsPerEntry',
	  cast(Snacks05SodiumGramsPerEntry             as decimal(8,2))                 'snacks05SodiumGramsPerEntry',
	  cast(Snacks05AlcoholGramsPerEntry            as decimal(8,1))                 'snacks05AlcoholGramsPerEntry',
	        Snacks06FoodDescription                                                  'snacks06FoodDescription',
	        Snacks06AmountDescription                                                'snacks06AmountDescription',
	  cast(Snacks06EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks06EnergyKiloJoulesPerEntry',
	  cast(Snacks06ProteinGramsPerEntry            as decimal(8,1))                 'snacks06ProteinGramsPerEntry',
	  cast(Snacks06CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks06CarbohydrateGramsPerEntry',
	  cast(Snacks06SugarGramsPerEntry              as decimal(8,1))                 'snacks06SugarGramsPerEntry',
	  cast(Snacks06StarchGramsPerEntry             as decimal(8,1))                 'snacks06StarchGramsPerEntry',
	  cast(Snacks06FatGramsPerEntry                as decimal(8,1))                 'snacks06FatGramsPerEntry',
	  cast(Snacks06SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks06SaturatedFatGramsPerEntry',
	  cast(Snacks06UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks06UnsaturatedFatGramsPerEntry',
	  cast(Snacks06CholesterolGramsPerEntry        as decimal(8,1))                 'snacks06CholesterolGramsPerEntry',
	  cast(Snacks06TransFatGramsPerEntry           as decimal(8,1))                 'snacks06TransFatGramsPerEntry',
	  cast(Snacks06DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks06DietaryFibreGramsPerEntry',
	  cast(Snacks06SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks06SolubleFibreGramsPerEntry',
	  cast(Snacks06InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks06InsolubleFibreGramsPerEntry',
	  cast(Snacks06SodiumGramsPerEntry             as decimal(8,2))                 'snacks06SodiumGramsPerEntry',
	  cast(Snacks06AlcoholGramsPerEntry            as decimal(8,1))                 'snacks06AlcoholGramsPerEntry',
	        Snacks07FoodDescription                                                  'snacks07FoodDescription',
	        Snacks07AmountDescription                                                'snacks07AmountDescription',
	  cast(Snacks07EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks07EnergyKiloJoulesPerEntry',
	  cast(Snacks07ProteinGramsPerEntry            as decimal(8,1))                 'snacks07ProteinGramsPerEntry',
	  cast(Snacks07CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks07CarbohydrateGramsPerEntry',
	  cast(Snacks07SugarGramsPerEntry              as decimal(8,1))                 'snacks07SugarGramsPerEntry',
	  cast(Snacks07StarchGramsPerEntry             as decimal(8,1))                 'snacks07StarchGramsPerEntry',
	  cast(Snacks07FatGramsPerEntry                as decimal(8,1))                 'snacks07FatGramsPerEntry',
	  cast(Snacks07SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks07SaturatedFatGramsPerEntry',
	  cast(Snacks07UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks07UnsaturatedFatGramsPerEntry',
	  cast(Snacks07CholesterolGramsPerEntry        as decimal(8,1))                 'snacks07CholesterolGramsPerEntry',
	  cast(Snacks07TransFatGramsPerEntry           as decimal(8,1))                 'snacks07TransFatGramsPerEntry',
	  cast(Snacks07DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks07DietaryFibreGramsPerEntry',
	  cast(Snacks07SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks07SolubleFibreGramsPerEntry',
	  cast(Snacks07InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks07InsolubleFibreGramsPerEntry',
	  cast(Snacks07SodiumGramsPerEntry             as decimal(8,2))                 'snacks07SodiumGramsPerEntry',
	  cast(Snacks07AlcoholGramsPerEntry            as decimal(8,1))                 'snacks07AlcoholGramsPerEntry',
	        Snacks08FoodDescription                                                  'snacks08FoodDescription',
	        Snacks08AmountDescription                                                'snacks08AmountDescription',
	  cast(Snacks08EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks08EnergyKiloJoulesPerEntry',
	  cast(Snacks08ProteinGramsPerEntry            as decimal(8,1))                 'snacks08ProteinGramsPerEntry',
	  cast(Snacks08CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks08CarbohydrateGramsPerEntry',
	  cast(Snacks08SugarGramsPerEntry              as decimal(8,1))                 'snacks08SugarGramsPerEntry',
	  cast(Snacks08StarchGramsPerEntry             as decimal(8,1))                 'snacks08StarchGramsPerEntry',
	  cast(Snacks08FatGramsPerEntry                as decimal(8,1))                 'snacks08FatGramsPerEntry',
	  cast(Snacks08SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks08SaturatedFatGramsPerEntry',
	  cast(Snacks08UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks08UnsaturatedFatGramsPerEntry',
	  cast(Snacks08CholesterolGramsPerEntry        as decimal(8,1))                 'snacks08CholesterolGramsPerEntry',
	  cast(Snacks08TransFatGramsPerEntry           as decimal(8,1))                 'snacks08TransFatGramsPerEntry',
	  cast(Snacks08DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks08DietaryFibreGramsPerEntry',
	  cast(Snacks08SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks08SolubleFibreGramsPerEntry',
	  cast(Snacks08InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks08InsolubleFibreGramsPerEntry',
	  cast(Snacks08SodiumGramsPerEntry             as decimal(8,2))                 'snacks08SodiumGramsPerEntry',
	  cast(Snacks08AlcoholGramsPerEntry            as decimal(8,1))                 'snacks08AlcoholGramsPerEntry',
	        Snacks09FoodDescription                                                  'snacks09FoodDescription',
	        Snacks09AmountDescription                                                'snacks09AmountDescription',
	  cast(Snacks09EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks09EnergyKiloJoulesPerEntry',
	  cast(Snacks09ProteinGramsPerEntry            as decimal(8,1))                 'snacks09ProteinGramsPerEntry',
	  cast(Snacks09CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks09CarbohydrateGramsPerEntry',
	  cast(Snacks09SugarGramsPerEntry              as decimal(8,1))                 'snacks09SugarGramsPerEntry',
	  cast(Snacks09StarchGramsPerEntry             as decimal(8,1))                 'snacks09StarchGramsPerEntry',
	  cast(Snacks09FatGramsPerEntry                as decimal(8,1))                 'snacks09FatGramsPerEntry',
	  cast(Snacks09SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks09SaturatedFatGramsPerEntry',
	  cast(Snacks09UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks09UnsaturatedFatGramsPerEntry',
	  cast(Snacks09CholesterolGramsPerEntry        as decimal(8,1))                 'snacks09CholesterolGramsPerEntry',
	  cast(Snacks09TransFatGramsPerEntry           as decimal(8,1))                 'snacks09TransFatGramsPerEntry',
	  cast(Snacks09DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks09DietaryFibreGramsPerEntry',
	  cast(Snacks09SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks09SolubleFibreGramsPerEntry',
	  cast(Snacks09InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks09InsolubleFibreGramsPerEntry',
	  cast(Snacks09SodiumGramsPerEntry             as decimal(8,2))                 'snacks09SodiumGramsPerEntry',
	  cast(Snacks09AlcoholGramsPerEntry            as decimal(8,1))                 'snacks09AlcoholGramsPerEntry',
	        Snacks10FoodDescription                                                  'snacks10FoodDescription',
	        Snacks10AmountDescription                                                'snacks10AmountDescription',
	  cast(Snacks10EnergyKiloJoulesPerEntry        as decimal(8,0))                 'snacks10EnergyKiloJoulesPerEntry',
	  cast(Snacks10ProteinGramsPerEntry            as decimal(8,1))                 'snacks10ProteinGramsPerEntry',
	  cast(Snacks10CarbohydrateGramsPerEntry       as decimal(8,1))                 'snacks10CarbohydrateGramsPerEntry',
	  cast(Snacks10SugarGramsPerEntry              as decimal(8,1))                 'snacks10SugarGramsPerEntry',
	  cast(Snacks10StarchGramsPerEntry             as decimal(8,1))                 'snacks10StarchGramsPerEntry',
	  cast(Snacks10FatGramsPerEntry                as decimal(8,1))                 'snacks10FatGramsPerEntry',
	  cast(Snacks10SaturatedFatGramsPerEntry       as decimal(8,1))                 'snacks10SaturatedFatGramsPerEntry',
	  cast(Snacks10UnsaturatedFatGramsPerEntry     as decimal(8,1))                 'snacks10UnsaturatedFatGramsPerEntry',
	  cast(Snacks10CholesterolGramsPerEntry        as decimal(8,1))                 'snacks10CholesterolGramsPerEntry',
	  cast(Snacks10TransFatGramsPerEntry           as decimal(8,1))                 'snacks10TransFatGramsPerEntry',
	  cast(Snacks10DietaryFibreGramsPerEntry       as decimal(8,1))                 'snacks10DietaryFibreGramsPerEntry',
	  cast(Snacks10SolubleFibreGramsPerEntry       as decimal(8,1))                 'snacks10SolubleFibreGramsPerEntry',
	  cast(Snacks10InsolubleFibreGramsPerEntry     as decimal(8,1))                 'snacks10InsolubleFibreGramsPerEntry',
	  cast(Snacks10SodiumGramsPerEntry             as decimal(8,2))                 'snacks10SodiumGramsPerEntry',
	  cast(Snacks10AlcoholGramsPerEntry            as decimal(8,1))                 'snacks10AlcoholGramsPerEntry',
	    
    Activity01AtTime                                    'activity01AtTime',
	  Activity01ActivityDescription                       'activity01ActivityDescription',
	  Activity01DurationHoursPerEntry                     'activity01DurationHoursPerEntry',
	  Activity01DistanceKilometersPerEntry                'activity01DistanceKilometersPerEntry',
	  Activity01EnergyKilojoulsPerEntry                   'activity01EnergyKilojoulsPerEntry',
	    
    Activity02AtTime                                    'activity02AtTime',
	  Activity02ActivityDescription                       'activity02ActivityDescription',
	  Activity02DurationHoursPerEntry                     'activity02DurationHoursPerEntry',
	  Activity02DistanceKilometersPerEntry                'activity02DistanceKilometersPerEntry',
	  Activity02EnergyKilojoulsPerEntry                   'activity02EnergyKilojoulsPerEntry',
	    
    Activity03AtTime                                    'activity03AtTime',
	  Activity03ActivityDescription                       'activity03ActivityDescription',
	  Activity03DurationHoursPerEntry                     'activity03DurationHoursPerEntry',
	  Activity03DistanceKilometersPerEntry                'activity03DistanceKilometersPerEntry',
	  Activity03EnergyKilojoulsPerEntry                   'activity03EnergyKilojoulsPerEntry',
	    
    Activity04AtTime                                    'activity04AtTime',
	  Activity04ActivityDescription                       'activity04ActivityDescription',
	  Activity04DurationHoursPerEntry                     'activity04DurationHoursPerEntry',
	  Activity04DistanceKilometersPerEntry                'activity04DistanceKilometersPerEntry',
	  Activity04EnergyKilojoulsPerEntry                   'activity04EnergyKilojoulsPerEntry',
	    
    Activity05AtTime                                    'activity05AtTime',
	  Activity05ActivityDescription                       'activity05ActivityDescription',
	  Activity05DurationHoursPerEntry                     'activity05DurationHoursPerEntry',
	  Activity05DistanceKilometersPerEntry                'activity05DistanceKilometersPerEntry',
	  Activity05EnergyKilojoulsPerEntry                   'activity05EnergyKilojoulsPerEntry',
	    
    Weight01AtTime                                      'weight01AtTime',
	  Weight01Kilograms                                   'weight01Kilograms',
	  Weight02AtTime                                      'weight02AtTime',
	  Weight02Kilograms                                   'weight02Kilograms',
	  Weight03AtTime                                      'weight03AtTime',
	  Weight03Kilograms                                   'weight03Kilograms',
	    
    BloodPressure01AtTime                               'bloodPressure01AtTime',
	  BloodPressure01MillimetersofMercury                 'bloodPressure01MillimetersofMercury',
	  BloodPressure02AtTime                               'bloodPressure02AtTime',
	  BloodPressure02MillimetersofMercury                 'bloodPressure02MillimetersofMercury',
	  BloodPressure03AtTime                               'bloodPressure03AtTime',
	  BloodPressure04MillimetersofMercury                 'bloodPressure04MillimetersofMercury',
	    
    HeartRate01AtTime                                   'heartRate01AtTime',
	  HeartRate01BeatsPerMinute                           'heartRate01BeatsPerMinute',
	  HeartRate02AtTime                                   'heartRate02AtTime',
	  HeartRate02BeatsPerMinute                           'heartRate02BeatsPerMinute',
	  HeartRate03AtTime                                   'heartRate03AtTime',
	  HeartRate03BeatsPerMinute                           'heartRate03BeatsPerMinute',
      
    Note                                                'note'
  FROM
    diary.Day
  WHERE
    PersonGUID = @PersonGUID  
  AND
    DayDate IN ( SELECT dayDate FROM @DATES )

END
--
RETURN @@ROWCOUNT
go

GRANT EXECUTE ON diary.GetDetails TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE diary.ProcessUpdateDay
(
  @PersonGUID                       uniqueidentifier, 

  @DayDate                          date,
  @MealName                         varchar(255), 
  @EntryNo                          tinyint, 

  @FoodDescription                  varchar(255),
  @AmountDescription                varchar(255),

  @EnergyKiloJoulesPerEntry         float = NULL,      
  @ProteinGramsPerEntry             float = NULL,          
  @CarbohydrateGramsPerEntry        float = NULL,     
  @SugarGramsPerEntry               float = NULL,            
  @StarchGramsPerEntry              float = NULL,           
  @FatGramsPerEntry                 float = NULL,              
  @SaturatedFatGramsPerEntry       float = NULL,    
  @UnsaturatedFatGramsPerEntry      float = NULL,   
  @CholesterolGramsPerEntry         float = NULL,      
  @TransFatGramsPerEntry            float = NULL,         
  @DietaryFibreGramsPerEntry        float = NULL,     
  @SolubleFibreGramsPerEntry        float = NULL,     
  @InsolubleFibreGramsPerEntry      float = NULL,   
  @SodiumGramsPerEntry              float = NULL,           
  @AlcoholGramsPerEntry             float = NULL
)
AS

IF UPPER(@MealName) = 'BREAKFAST' BEGIN

  IF @EntryNo = 1 BEGIN

    UPDATE diary.day SET

	    Breakfast01FoodDescription                = @FoodDescription,              
	    Breakfast01AmountDescription              = @AmountDescription,    
	    Breakfast01EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast01ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast01CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast01SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast01StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast01FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast01SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast01UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast01CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast01TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast01DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast01SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast01InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast01SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast01AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 2 BEGIN

    UPDATE diary.day SET

	    Breakfast02FoodDescription                = @FoodDescription,              
	    Breakfast02AmountDescription              = @AmountDescription,    
	    Breakfast02EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast02ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast02CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast02SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast02StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast02FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast02SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast02UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast02CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast02TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast02DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast02SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast02InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast02SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast02AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 3 BEGIN

    UPDATE diary.day SET

	    Breakfast03FoodDescription                = @FoodDescription,              
	    Breakfast03AmountDescription              = @AmountDescription,    
	    Breakfast03EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast03ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast03CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast03SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast03StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast03FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast03SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast03UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast03CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast03TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast03DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast03SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast03InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast03SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast03AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 4 BEGIN

    UPDATE diary.day SET

	    Breakfast04FoodDescription                = @FoodDescription,              
	    Breakfast04AmountDescription              = @AmountDescription,    
	    Breakfast04EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast04ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast04CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast04SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast04StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast04FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast04SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast04UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast04CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast04TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast04DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast04SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast04InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast04SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast04AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 5 BEGIN

    UPDATE diary.day SET

	    Breakfast05FoodDescription                = @FoodDescription,              
	    Breakfast05AmountDescription              = @AmountDescription,          
	    Breakfast05EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast05ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast05CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast05SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast05StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast05FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast05SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast05UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast05CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast05TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast05DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast05SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast05InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast05SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast05AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 6 BEGIN

    UPDATE diary.day SET

	    Breakfast06FoodDescription                = @FoodDescription,              
	    Breakfast06AmountDescription              = @AmountDescription,    
	    Breakfast06EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast06ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast06CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast06SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast06StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast06FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast06SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast06UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast06CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast06TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast06DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast06SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast06InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast06SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast06AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 7 BEGIN

    UPDATE diary.day SET

	    Breakfast07FoodDescription                = @FoodDescription,              
	    Breakfast07AmountDescription              = @AmountDescription,    
	    Breakfast07EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast07ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast07CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast07SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast07StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast07FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast07SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast07UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast07CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast07TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast07DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast07SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast07InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast07SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast07AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 8 BEGIN

    UPDATE diary.day SET

	    Breakfast08FoodDescription                = @FoodDescription,              
	    Breakfast08AmountDescription              = @AmountDescription,    
	    Breakfast08EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast08ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast08CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast08SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast08StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast08FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast08SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast08UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast08CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast08TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast08DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast08SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast08InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast08SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast08AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 9 BEGIN

    UPDATE diary.day SET

	    Breakfast09FoodDescription                = @FoodDescription,              
	    Breakfast09AmountDescription              = @AmountDescription,    
	    Breakfast09EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast09ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast09CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast09SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast09StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast09FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast09SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast09UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast09CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast09TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast09DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast09SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast09InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast09SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast09AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 10 BEGIN

    UPDATE diary.day SET

	    Breakfast10FoodDescription                = @FoodDescription,              
	    Breakfast10AmountDescription              = @AmountDescription,    
	    Breakfast10EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Breakfast10ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Breakfast10CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Breakfast10SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Breakfast10StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Breakfast10FatGramsPerEntry               = @FatGramsPerEntry,               
	    Breakfast10SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Breakfast10UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Breakfast10CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Breakfast10TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Breakfast10DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Breakfast10SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Breakfast10InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Breakfast10SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Breakfast10AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END 

END

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ELSE IF UPPER(@MealName) = 'LUNCH' BEGIN

  IF @EntryNo = 1 BEGIN

    UPDATE diary.day SET

	    Lunch01FoodDescription                = @FoodDescription,              
	    Lunch01AmountDescription              = @AmountDescription,    
	    Lunch01EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch01ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch01CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch01SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch01StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch01FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch01SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch01UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch01CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch01TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch01DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch01SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch01InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch01SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch01AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 2 BEGIN

    UPDATE diary.day SET

	    Lunch02FoodDescription                = @FoodDescription,              
	    Lunch02AmountDescription              = @AmountDescription,    
	    Lunch02EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch02ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch02CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch02SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch02StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch02FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch02SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch02UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch02CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch02TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch02DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch02SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch02InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch02SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch02AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 3 BEGIN

    UPDATE diary.day SET

	    Lunch03FoodDescription                = @FoodDescription,              
	    Lunch03AmountDescription              = @AmountDescription,    
	    Lunch03EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch03ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch03CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch03SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch03StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch03FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch03SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch03UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch03CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch03TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch03DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch03SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch03InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch03SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch03AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 4 BEGIN

    UPDATE diary.day SET

	    Lunch04FoodDescription                = @FoodDescription,              
	    Lunch04AmountDescription              = @AmountDescription,    
	    Lunch04EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch04ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch04CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch04SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch04StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch04FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch04SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch04UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch04CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch04TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch04DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch04SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch04InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch04SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch04AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 5 BEGIN

    UPDATE diary.day SET

	    Lunch05FoodDescription                = @FoodDescription,              
	    Lunch05AmountDescription              = @AmountDescription,          
	    Lunch05EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch05ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch05CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch05SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch05StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch05FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch05SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch05UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch05CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch05TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch05DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch05SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch05InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch05SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch05AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 6 BEGIN

    UPDATE diary.day SET

	    Lunch06FoodDescription                = @FoodDescription,              
	    Lunch06AmountDescription              = @AmountDescription,    
	    Lunch06EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch06ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch06CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch06SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch06StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch06FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch06SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch06UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch06CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch06TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch06DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch06SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch06InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch06SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch06AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 7 BEGIN

    UPDATE diary.day SET

	    Lunch07FoodDescription                = @FoodDescription,              
	    Lunch07AmountDescription              = @AmountDescription,    
	    Lunch07EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch07ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch07CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch07SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch07StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch07FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch07SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch07UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch07CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch07TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch07DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch07SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch07InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch07SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch07AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 8 BEGIN

    UPDATE diary.day SET

	    Lunch08FoodDescription                = @FoodDescription,              
	    Lunch08AmountDescription              = @AmountDescription,    
	    Lunch08EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch08ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch08CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch08SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch08StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch08FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch08SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch08UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch08CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch08TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch08DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch08SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch08InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch08SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch08AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 9 BEGIN

    UPDATE diary.day SET

	    Lunch09FoodDescription                = @FoodDescription,              
	    Lunch09AmountDescription              = @AmountDescription,    
	    Lunch09EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch09ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch09CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch09SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch09StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch09FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch09SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch09UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch09CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch09TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch09DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch09SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch09InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch09SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch09AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 10 BEGIN

    UPDATE diary.day SET

	    Lunch10FoodDescription                = @FoodDescription,              
	    Lunch10AmountDescription              = @AmountDescription,    
	    Lunch10EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Lunch10ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Lunch10CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Lunch10SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Lunch10StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Lunch10FatGramsPerEntry               = @FatGramsPerEntry,               
	    Lunch10SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Lunch10UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Lunch10CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Lunch10TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Lunch10DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Lunch10SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Lunch10InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Lunch10SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Lunch10AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END  

END

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ELSE IF UPPER(@MealName) = 'DINNER' BEGIN

  IF @EntryNo = 1 BEGIN

    UPDATE diary.day SET

	    Dinner01FoodDescription                = @FoodDescription,              
	    Dinner01AmountDescription              = @AmountDescription,    
	    Dinner01EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner01ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner01CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner01SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner01StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner01FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner01SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner01UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner01CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner01TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner01DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner01SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner01InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner01SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner01AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 2 BEGIN

    UPDATE diary.day SET

	    Dinner02FoodDescription                = @FoodDescription,              
	    Dinner02AmountDescription              = @AmountDescription,    
	    Dinner02EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner02ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner02CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner02SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner02StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner02FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner02SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner02UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner02CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner02TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner02DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner02SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner02InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner02SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner02AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 3 BEGIN

    UPDATE diary.day SET

	    Dinner03FoodDescription                = @FoodDescription,              
	    Dinner03AmountDescription              = @AmountDescription,    
	    Dinner03EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner03ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner03CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner03SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner03StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner03FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner03SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner03UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner03CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner03TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner03DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner03SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner03InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner03SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner03AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 4 BEGIN

    UPDATE diary.day SET

	    Dinner04FoodDescription                = @FoodDescription,              
	    Dinner04AmountDescription              = @AmountDescription,    
	    Dinner04EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner04ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner04CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner04SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner04StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner04FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner04SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner04UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner04CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner04TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner04DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner04SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner04InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner04SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner04AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 5 BEGIN

    UPDATE diary.day SET

	    Dinner05FoodDescription                = @FoodDescription,              
	    Dinner05AmountDescription              = @AmountDescription,          
	    Dinner05EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner05ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner05CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner05SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner05StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner05FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner05SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner05UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner05CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner05TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner05DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner05SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner05InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner05SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner05AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 6 BEGIN

    UPDATE diary.day SET

	    Dinner06FoodDescription                = @FoodDescription,              
	    Dinner06AmountDescription              = @AmountDescription,    
	    Dinner06EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner06ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner06CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner06SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner06StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner06FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner06SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner06UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner06CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner06TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner06DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner06SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner06InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner06SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner06AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 7 BEGIN

    UPDATE diary.day SET

	    Dinner07FoodDescription                = @FoodDescription,              
	    Dinner07AmountDescription              = @AmountDescription,    
	    Dinner07EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner07ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner07CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner07SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner07StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner07FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner07SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner07UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner07CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner07TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner07DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner07SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner07InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner07SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner07AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 8 BEGIN

    UPDATE diary.day SET

	    Dinner08FoodDescription                = @FoodDescription,              
	    Dinner08AmountDescription              = @AmountDescription,    
	    Dinner08EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner08ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner08CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner08SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner08StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner08FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner08SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner08UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner08CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner08TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner08DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner08SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner08InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner08SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner08AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 9 BEGIN

    UPDATE diary.day SET

	    Dinner09FoodDescription                = @FoodDescription,              
	    Dinner09AmountDescription              = @AmountDescription,    
	    Dinner09EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner09ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner09CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner09SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner09StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner09FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner09SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner09UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner09CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner09TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner09DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner09SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner09InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner09SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner09AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 10 BEGIN

    UPDATE diary.day SET

	    Dinner10FoodDescription                = @FoodDescription,              
	    Dinner10AmountDescription              = @AmountDescription,    
	    Dinner10EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Dinner10ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Dinner10CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Dinner10SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Dinner10StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Dinner10FatGramsPerEntry               = @FatGramsPerEntry,               
	    Dinner10SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Dinner10UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Dinner10CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Dinner10TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Dinner10DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Dinner10SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Dinner10InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Dinner10SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Dinner10AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END  

END

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

ELSE IF UPPER(@MealName) = 'SNACKS' BEGIN

   IF @EntryNo = 1 BEGIN

    UPDATE diary.day SET

	    Snacks01FoodDescription                = @FoodDescription,              
	    Snacks01AmountDescription              = @AmountDescription,    
	    Snacks01EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks01ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks01CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks01SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks01StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks01FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks01SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks01UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks01CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks01TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks01DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks01SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks01InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks01SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks01AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 2 BEGIN

    UPDATE diary.day SET

	    Snacks02FoodDescription                = @FoodDescription,              
	    Snacks02AmountDescription              = @AmountDescription,    
	    Snacks02EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks02ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks02CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks02SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks02StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks02FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks02SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks02UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks02CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks02TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks02DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks02SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks02InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks02SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks02AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 3 BEGIN

    UPDATE diary.day SET

	    Snacks03FoodDescription                = @FoodDescription,              
	    Snacks03AmountDescription              = @AmountDescription,    
	    Snacks03EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks03ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks03CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks03SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks03StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks03FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks03SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks03UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks03CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks03TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks03DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks03SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks03InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks03SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks03AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 4 BEGIN

    UPDATE diary.day SET

	    Snacks04FoodDescription                = @FoodDescription,              
	    Snacks04AmountDescription              = @AmountDescription,    
	    Snacks04EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks04ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks04CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks04SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks04StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks04FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks04SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks04UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks04CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks04TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks04DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks04SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks04InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks04SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks04AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 5 BEGIN

    UPDATE diary.day SET

	    Snacks05FoodDescription                = @FoodDescription,              
	    Snacks05AmountDescription              = @AmountDescription,          
	    Snacks05EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks05ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks05CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks05SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks05StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks05FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks05SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks05UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks05CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks05TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks05DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks05SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks05InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks05SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks05AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 6 BEGIN

    UPDATE diary.day SET

	    Snacks06FoodDescription                = @FoodDescription,              
	    Snacks06AmountDescription              = @AmountDescription,    
	    Snacks06EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks06ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks06CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks06SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks06StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks06FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks06SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks06UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks06CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks06TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks06DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks06SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks06InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks06SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks06AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 7 BEGIN

    UPDATE diary.day SET

	    Snacks07FoodDescription                = @FoodDescription,              
	    Snacks07AmountDescription              = @AmountDescription,    
	    Snacks07EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks07ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks07CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks07SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks07StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks07FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks07SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks07UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks07CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks07TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks07DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks07SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks07InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks07SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks07AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 8 BEGIN

    UPDATE diary.day SET

	    Snacks08FoodDescription                = @FoodDescription,              
	    Snacks08AmountDescription              = @AmountDescription,    
	    Snacks08EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks08ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks08CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks08SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks08StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks08FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks08SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks08UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks08CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks08TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks08DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks08SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks08InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks08SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks08AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 9 BEGIN

    UPDATE diary.day SET

	    Snacks09FoodDescription                = @FoodDescription,              
	    Snacks09AmountDescription              = @AmountDescription,    
	    Snacks09EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks09ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks09CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks09SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks09StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks09FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks09SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks09UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks09CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks09TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks09DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks09SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks09InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks09SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks09AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END ELSE IF @EntryNo = 10 BEGIN

    UPDATE diary.day SET

	    Snacks10FoodDescription                = @FoodDescription,              
	    Snacks10AmountDescription              = @AmountDescription,    
	    Snacks10EnergyKiloJoulesPerEntry       = @EnergyKiloJoulesPerEntry,       
	    Snacks10ProteinGramsPerEntry           = @ProteinGramsPerEntry,           
	    Snacks10CarbohydrateGramsPerEntry      = @CarbohydrateGramsPerEntry,      
	    Snacks10SugarGramsPerEntry             = @SugarGramsPerEntry,             
	    Snacks10StarchGramsPerEntry            = @StarchGramsPerEntry,            
	    Snacks10FatGramsPerEntry               = @FatGramsPerEntry,               
	    Snacks10SaturatedFatGramsPerEntry      = @SaturatedFatGramsPerEntry,     
	    Snacks10UnsaturatedFatGramsPerEntry    = @UnsaturatedFatGramsPerEntry,    
	    Snacks10CholesterolGramsPerEntry       = @CholesterolGramsPerEntry,       
	    Snacks10TransFatGramsPerEntry          = @TransFatGramsPerEntry,          
	    Snacks10DietaryFibreGramsPerEntry      = @DietaryFibreGramsPerEntry,      
	    Snacks10SolubleFibreGramsPerEntry      = @SolubleFibreGramsPerEntry,      
	    Snacks10InsolubleFibreGramsPerEntry    = @InsolubleFibreGramsPerEntry,    
	    Snacks10SodiumGramsPerEntry            = @SodiumGramsPerEntry,            
	    Snacks10AlcoholGramsPerEntry           = @AlcoholGramsPerEntry          
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

  END 

END

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
IF @@ROWCOUNT > 0 BEGIN

    EXECUTE  diary.ProcessCalculateDay  @PersonGUID, @DayDate

    UPDATE diary.day SET
      EditCount = EditCount + 1
    WHERE
      PersonGUID = @PersonGUID AND DayDate = @DayDate

END

RETURN @@rowcount
go

REVOKE EXECUTE ON diary.ProcessUpdateDay TO eatandoData
GO

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-- security.GetAuthorizationForExistingUser 'daniel.payne@keldan.co.uk', '123', '127.0.0.1'
-- EXECUTE diary.PostFoodEntry  '612A7D6A-5FD6-42F4-B849-4D58E3FC2D57', 'pork pie', 150g', '2016-04-15', 'breakfast'
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CREATE PROCEDURE diary.PostFoodEntry
(
   @SessionGUID     uniqueidentifier,

   @DayDate           date,
   @MealName          varchar(255),

   @FoodDescription   varchar(255),
   @AmountDescription varchar(255), 

   @EnergyKiloJoulesPerEntry         float = null, 
   @ProteinGramsPerEntry             float = null, 
   @CarbohydrateGramsPerEntry        float = null, 
   @SugarGramsPerEntry               float = null, 
   @StarchGramsPerEntry              float = null, 
   @FatGramsPerEntry                 float = null, 
   @SaturatedFatGramsPerEntry        float = null, 
   @UnsaturatedFatGramsPerEntry      float = null, 
   @CholesterolGramsPerEntry         float = null, 
   @TransFatGramsPerEntry            float = null, 
   @DietaryFibreGramsPerEntry        float = null, 
   @SolubleFibreGramsPerEntry        float = null, 
   @InsolubleFibreGramsPerEntry      float = null, 
   @SodiumGramsPerEntry              float = null, 
   @AlcoholGramsPerEntry             float = null
)
AS
 
DECLARE
  @PersonGUID  uniqueidentifier,
  @Now         date = getutcdate(),
  @EntryNo     integer 

SELECT
  @PersonGUID = PersonGUID
FROM
  security.Session
WHERE
  SessionGUID = @SessionGUID
AND
  IsActive    = 1
AND
  SessionExpiresUTC > @Now

IF @PersonGUID IS NULL BEGIN

   return 0

END
 
IF NOT EXISTS (SELECT 1 FROM diary.Day WHERE PersonGUID = @PersonGUID AND DayDate = @DayDate) BEGIN

   INSERT INTO diary.Day (PersonGUID, DayDate, EditCount)
   VALUES(@PersonGUID, @DayDate, 0)

END 

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

IF UPPER(@MealName) = 'BREAKFAST' BEGIN
 
  SELECT
    @EntryNo = 
      CASE 
        WHEN Breakfast01FoodDescription IS NULL THEN 01 
        WHEN Breakfast02FoodDescription IS NULL THEN 02 
        WHEN Breakfast03FoodDescription IS NULL THEN 03 
        WHEN Breakfast04FoodDescription IS NULL THEN 04 
        WHEN Breakfast05FoodDescription IS NULL THEN 05 
        WHEN Breakfast06FoodDescription IS NULL THEN 06 
        WHEN Breakfast07FoodDescription IS NULL THEN 07 
        WHEN Breakfast08FoodDescription IS NULL THEN 08 
        WHEN Breakfast09FoodDescription IS NULL THEN 09 
        WHEN Breakfast10FoodDescription IS NULL THEN 10 
      END
  FROM
    diary.Day
  WHERE
    PersonGUID = @PersonGUID
  AND
    DayDate    = @DayDate 

END ELSE IF UPPER(@MealName) = 'LUNCH' BEGIN
 
  SELECT
    @EntryNo = 
      CASE 
        WHEN Lunch01FoodDescription IS NULL THEN 01 
        WHEN Lunch02FoodDescription IS NULL THEN 02 
        WHEN Lunch03FoodDescription IS NULL THEN 03 
        WHEN Lunch04FoodDescription IS NULL THEN 04 
        WHEN Lunch05FoodDescription IS NULL THEN 05 
        WHEN Lunch06FoodDescription IS NULL THEN 06 
        WHEN Lunch07FoodDescription IS NULL THEN 07 
        WHEN Lunch08FoodDescription IS NULL THEN 08 
        WHEN Lunch09FoodDescription IS NULL THEN 09 
        WHEN Lunch10FoodDescription IS NULL THEN 10 
      END
  FROM
    diary.Day
  WHERE
    PersonGUID = @PersonGUID
  AND
    DayDate    = @DayDate 

END ELSE IF UPPER(@MealName) = 'DINNER' BEGIN
 
  SELECT
    @EntryNo = 
      CASE 
        WHEN Dinner01FoodDescription IS NULL THEN 01 
        WHEN Dinner02FoodDescription IS NULL THEN 02 
        WHEN Dinner03FoodDescription IS NULL THEN 03 
        WHEN Dinner04FoodDescription IS NULL THEN 04 
        WHEN Dinner05FoodDescription IS NULL THEN 05 
        WHEN Dinner06FoodDescription IS NULL THEN 06 
        WHEN Dinner07FoodDescription IS NULL THEN 07 
        WHEN Dinner08FoodDescription IS NULL THEN 08 
        WHEN Dinner09FoodDescription IS NULL THEN 09 
        WHEN Dinner10FoodDescription IS NULL THEN 10 
      END
  FROM
    diary.Day
  WHERE
    PersonGUID = @PersonGUID
  AND
    DayDate    = @DayDate 

END ELSE IF UPPER(@MealName) = 'SNACKS' BEGIN
 
  SELECT
    @EntryNo = 
      CASE 
        WHEN Snacks01FoodDescription IS NULL THEN 01 
        WHEN Snacks02FoodDescription IS NULL THEN 02 
        WHEN Snacks03FoodDescription IS NULL THEN 03 
        WHEN Snacks04FoodDescription IS NULL THEN 04 
        WHEN Snacks05FoodDescription IS NULL THEN 05 
        WHEN Snacks06FoodDescription IS NULL THEN 06 
        WHEN Snacks07FoodDescription IS NULL THEN 07 
        WHEN Snacks08FoodDescription IS NULL THEN 08 
        WHEN Snacks09FoodDescription IS NULL THEN 09 
        WHEN Snacks10FoodDescription IS NULL THEN 10 
      END
  FROM
    diary.Day
  WHERE
    PersonGUID = @PersonGUID
  AND
    DayDate    = @DayDate 

END

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

DECLARE
  @OldEditCount integer,
  @NewEditCount integer

SELECT
  @OldEditCount = EditCount  
FROM
  diary.Day
WHERE
  PersonGUID = @PersonGUID AND DayDate = @DayDate

EXECUTE diary.ProcessUpdateDay 
          @PersonGUID, 
          @DayDate, 
          @MealName,
          @EntryNo, 

          @FoodDescription,
          @AmountDescription,  

          @EnergyKiloJoulesPerEntry,      
          @ProteinGramsPerEntry,          
          @CarbohydrateGramsPerEntry,     
          @SugarGramsPerEntry,            
          @StarchGramsPerEntry,           
          @FatGramsPerEntry,              
          @SaturatedFatGramsPerEntry,    
          @UnsaturatedFatGramsPerEntry,   
          @CholesterolGramsPerEntry,      
          @TransFatGramsPerEntry,         
          @DietaryFibreGramsPerEntry,     
          @SolubleFibreGramsPerEntry,     
          @InsolubleFibreGramsPerEntry,   
          @SodiumGramsPerEntry,           
          @AlcoholGramsPerEntry   
          
SELECT
  @NewEditCount = EditCount  
FROM
  diary.Day
WHERE
  PersonGUID = @PersonGUID 
AND 
  DayDate    = @DayDate

IF (@NewEditCount !=  @OldEditCount) BEGIN

  EXECUTE diary.GetDetails @sessionGUID, @DayDate

END
                 
RETURN @@rowcount                       
go

GRANT EXECUTE ON diary.PostFoodEntry TO eatandoData
GO

