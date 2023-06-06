import { testProp, fc } from '@fast-check/jest';
import { parseQuestionRecords, QClass, QType, generateLabels, encodeUInt16BE, concatUInt8Array, generateQuestionRecord, parseQuestionRecord } from '@/dns';

// For all integers in set of values in QType/QClass
const FC_QTYPES = fc.constantFrom(QType.A, QType.AAAA, QType.ANY, QType.CNAME, QType.NSEC, QType.OPT, QType.PTR, QType.TXT, QType.SRV);
const FC_QCLASSES = fc.constantFrom(QClass.ANY, QClass.IN);

const fc_question = fc.record({
  name: fc.domain(),
  type: FC_QTYPES,
  class: FC_QCLASSES,
  unicast: fc.boolean()
});

const fc_question_no_unicast = fc.record({
  name: fc.domain(),
  type: FC_QTYPES,
  class: FC_QCLASSES,
  unicast: fc.constant(false)
});

describe('question records', () => {
  testProp('parse', [fc_question_no_unicast], (originalQuestion) => {
    const generatedQuestion = generateQuestionRecord(originalQuestion);
    const parsedQuestion = parseQuestionRecord(generatedQuestion, generatedQuestion);
    expect(parsedQuestion.data).toEqual(originalQuestion);
  });
  testProp('parse single string name', [fc_question_no_unicast], (originalQuestion) => {

    const rawQuestion = concatUInt8Array(
      generateLabels(originalQuestion.name),
      encodeUInt16BE(originalQuestion.type),
      encodeUInt16BE(originalQuestion.class)
    );

    const decodedQuestion = parseQuestionRecords(rawQuestion, rawQuestion, 1);

    expect(decodedQuestion.data).toEqual([originalQuestion]);
  });

  testProp(
    'parse multiple string name',
    [fc.array(fc_question_no_unicast, { minLength: 2, maxLength: 10 })],
    (originalQuestions) => {
      const originalQuestionUint8Array = originalQuestions.flatMap((q) => {
        return [
          ...generateLabels(q.name),
          ...encodeUInt16BE(q.type),
          ...encodeUInt16BE(q.class),
        ];
      });

      const rawQuestion = new Uint8Array(originalQuestionUint8Array);

      const decodedQuestion = parseQuestionRecords(
        rawQuestion,
        rawQuestion,
        originalQuestions.length,
      );

      expect(decodedQuestion.data).toEqual(originalQuestions);
      expect(decodedQuestion.remainder.length).toEqual(0);
    },
  );

  testProp('parse pointer name', [fc_question_no_unicast], (originalQuestion) => {
    // Universal Type and Class
    const typeAndClass = concatUInt8Array(
      encodeUInt16BE(originalQuestion.type),
      encodeUInt16BE(originalQuestion.class),
    );

    // Question with fake name to see if the pointer will select the correct record
    const questionWithFakeName = concatUInt8Array(
      generateLabels('fake.local'),
      typeAndClass,
    );

    // Uint8Array with a question and a pointer to that question
    const rawQuestion = concatUInt8Array(
      questionWithFakeName,
      generateLabels(originalQuestion.name),
      typeAndClass,

      // Pointer Question Starts with 0xC0
      new Uint8Array([0xc0, questionWithFakeName.byteLength]),
      typeAndClass,
    );

    const decodedQuestion = parseQuestionRecords(rawQuestion, rawQuestion, 3);

    expect(decodedQuestion.data[2].name).toEqual(originalQuestion.name);
    expect(decodedQuestion.remainder.length).toEqual(0);
  });

  testProp(
    'parse string pointer name',
    [fc_question_no_unicast, fc.domain()],
    (originalQuestion, randomDomain) => {
      // Universal Type and Class
      const typeAndClass = concatUInt8Array(
        encodeUInt16BE(originalQuestion.type),
        encodeUInt16BE(originalQuestion.class),
      );

      // Uint8Array with a question and a pointer to that question
      const rawQuestion = concatUInt8Array(
        generateLabels(originalQuestion.name),
        typeAndClass,

        // Pointer Question Starts with 0xC0
        generateLabels(randomDomain, [0xc0, 0]),
        typeAndClass,
      );

      const decodedQuestion = parseQuestionRecords(rawQuestion, rawQuestion, 2);

      expect(decodedQuestion.data[1].name).toEqual(`${randomDomain}.${originalQuestion.name}`);
      expect(decodedQuestion.remainder.length).toEqual(0);
    }
  );
});
